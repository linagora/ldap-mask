// config.go — configuration loading, ${ENV} expansion, validation.
package main

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

// Config is the root of the YAML file (see DESIGN.md §5).
type Config struct {
	Listen            string         `yaml:"listen"`
	TLS               TLSConfig      `yaml:"tls"`
	Upstream          UpstreamConfig `yaml:"upstream"`
	Mappings          []Mapping      `yaml:"mappings"`
	AllowUnmappedBind bool           `yaml:"allow_unmapped_bind"`
}

// TLSConfig describes the certificate presented to clients (LDAPS).
type TLSConfig struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

// UpstreamConfig describes the destination directory.
type UpstreamConfig struct {
	URL                string `yaml:"url"` // ldap:// or ldaps://
	CAFile             string `yaml:"ca_file"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
}

// Mapping associates a dummy local pair with a real upstream pair.
type Mapping struct {
	LocalDN             string `yaml:"local_dn"`
	LocalPasswordBcrypt string `yaml:"local_password_bcrypt"`
	RemoteDN            string `yaml:"remote_dn"`
	RemotePassword      string `yaml:"remote_password"`
}

// envVarRe recognises the ${VAR} syntax (design §5).
var envVarRe = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// expandEnv replaces ${VAR} with their value, and returns an error as soon as a
// referenced variable is missing. We do not use os.ExpandEnv, which would
// silently replace it with an empty string: a missing secret must make startup
// fail.
func expandEnv(s string) (string, error) {
	var missing error
	out := envVarRe.ReplaceAllStringFunc(s, func(match string) string {
		name := envVarRe.FindStringSubmatch(match)[1]
		value, ok := os.LookupEnv(name)
		if !ok && missing == nil {
			missing = fmt.Errorf("environment variable %q not defined", name)
		}
		return value
	})
	if missing != nil {
		return "", missing
	}
	return out, nil
}

// Load reads the file, resolves the ${VAR} then validates the configuration.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading configuration %q: %w", path, err)
	}

	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("invalid YAML configuration: %w", err)
	}

	for i := range c.Mappings {
		m := &c.Mappings[i]
		if m.RemoteDN, err = expandEnv(m.RemoteDN); err != nil {
			return nil, fmt.Errorf("mapping %d (local_dn %q): remote_dn: %w", i, m.LocalDN, err)
		}
		if m.RemotePassword, err = expandEnv(m.RemotePassword); err != nil {
			return nil, fmt.Errorf("mapping %d (local_dn %q): remote_password: %w", i, m.LocalDN, err)
		}
	}

	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// ListenScheme returns the scheme declared in `listen`: "ldap" (cleartext) or
// "ldaps" (TLS).
//
// The scheme is MANDATORY. Without it, nothing distinguishes a cleartext
// listener from a TLS listener, and a misreading would serve in cleartext a
// proxy believed to be encrypted — exactly the kind of doubt a debug tool must
// not leave hanging.
func (c *Config) ListenScheme() (string, error) {
	u, err := url.Parse(c.Listen)
	if err != nil {
		// The scheme may be present but the rest malformed (non-numeric port,
		// space…): say so, rather than demand a scheme.
		return "", fmt.Errorf("listen %q invalid (expected \"ldap://host:port\" or \"ldaps://host:port\"): %w", c.Listen, err)
	}
	switch u.Scheme {
	case "ldap", "ldaps":
		return u.Scheme, nil
	default:
		return "", fmt.Errorf("listen %q: specify the scheme, \"ldap://%s\" (cleartext) or \"ldaps://%s\" (TLS)", c.Listen, c.Listen, c.Listen)
	}
}

// ListenAddr returns the listener host:port address, with the scheme's default
// port (389 in cleartext, 636 in TLS) when it is not specified.
func (c *Config) ListenAddr() (string, error) {
	scheme, err := c.ListenScheme()
	if err != nil {
		return "", err
	}
	u, err := url.Parse(c.Listen)
	if err != nil {
		return "", fmt.Errorf("listen %q invalid: %w", c.Listen, err)
	}

	// A listener address has neither credentials nor path. Accepting them
	// silently would be worse than useless: a userinfo would be ignored… after
	// having been logged as is at startup.
	if u.User != nil {
		return "", fmt.Errorf("listen %q: unexpected credentials in a listener address", c.Listen)
	}
	if u.Path != "" && u.Path != "/" {
		return "", fmt.Errorf("listen %q: unexpected path, only the listener address is read", c.Listen)
	}
	if u.Hostname() == "" {
		return "", fmt.Errorf("listen %q: missing host", c.Listen)
	}

	port := u.Port()
	if port != "" {
		// 0 is accepted: "take a free port" is a legitimate request (test
		// benches, ephemeral listener). It is the only zero value that makes
		// sense here.
		n, err := strconv.Atoi(port)
		if err != nil || n < 0 || n > 65535 {
			return "", fmt.Errorf("listen %q: invalid port %q (0 to 65535)", c.Listen, port)
		}
		// url.Parse splits an UNBRACKETED IPv6 literal at the wrong colon:
		// "ldaps://::1" yields Hostname ":" and Port "1", so u.Host comes back
		// as "::1". Returning it would defer the failure to net.Listen, which
		// reports "missing port in address" (or "too many colons") — a message
		// that says nothing about the actual mistake. Check the result is a
		// usable host:port here instead.
		if _, _, err := net.SplitHostPort(u.Host); err != nil {
			return "", fmt.Errorf("listen %q: an IPv6 literal must be bracketed, e.g. ldaps://[::1]:1636", c.Listen)
		}
		return u.Host, nil
	}
	if scheme == "ldaps" {
		return net.JoinHostPort(u.Hostname(), "636"), nil
	}
	return net.JoinHostPort(u.Hostname(), "389"), nil
}

// UpstreamScheme returns "ldap" or "ldaps" for the upstream.
func (c *Config) UpstreamScheme() string {
	u, err := url.Parse(c.Upstream.URL)
	if err != nil {
		return ""
	}
	return u.Scheme
}

// NormalizeDN produces a lookup key.
//
// WARNING: this is an accepted approximation (design §5). We only lowercase and
// strip the spaces around commas. This is NOT a DN parser: escaping (\+, \"…),
// quotes and significant spaces are not handled. To be replaced by a compliant
// parser if the need arises.
func NormalizeDN(s string) string {
	parts := strings.Split(s, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return strings.ToLower(strings.Join(parts, ","))
}

// Lookup returns the mapping matching the local DN (normalized comparison), or
// nil if none matches.
func (c *Config) Lookup(localDN string) *Mapping {
	key := NormalizeDN(localDN)
	for i := range c.Mappings {
		if NormalizeDN(c.Mappings[i].LocalDN) == key {
			return &c.Mappings[i]
		}
	}
	return nil
}

// Validate checks the consistency of the configuration and returns a clear
// message in case of a problem.
func (c *Config) Validate() error {
	if strings.TrimSpace(c.Listen) == "" {
		return errors.New("listen: listener address mandatory")
	}
	scheme, err := c.ListenScheme()
	if err != nil {
		return err
	}
	if _, err := c.ListenAddr(); err != nil {
		return err
	}
	// The certificate is needed only for a TLS listener: a debug tool must be
	// able to serve in cleartext without having to craft a certificate.
	if scheme == "ldaps" && (c.TLS.CertFile == "" || c.TLS.KeyFile == "") {
		return errors.New("tls: cert_file and key_file are mandatory for a listener on ldaps://")
	}

	u, err := url.Parse(c.Upstream.URL)
	if err != nil {
		return fmt.Errorf("upstream.url %q invalid: %w", c.Upstream.URL, err)
	}
	if u.Scheme != "ldap" && u.Scheme != "ldaps" {
		return fmt.Errorf("upstream.url %q: expected ldap:// or ldaps:// scheme", c.Upstream.URL)
	}
	if u.Host == "" {
		return fmt.Errorf("upstream.url %q: missing host", c.Upstream.URL)
	}
	// The upstream credentials come from the mappings (remote_dn /
	// remote_password), never from the URL: a userinfo here would be ignored
	// silently, whereas it would have required writing the real password in
	// cleartext on disk (§6.2).
	if u.User != nil {
		return fmt.Errorf("upstream.url %q: unexpected credentials, they are declared in the mappings (remote_dn / remote_password)", c.Upstream.URL)
	}

	// §6.4: TLS on both sides is non-negotiable. We therefore refuse to disable
	// verification of the upstream certificate, except by explicit exemption
	// through an environment variable (useful in tests only).
	if c.Upstream.InsecureSkipVerify && os.Getenv("LDAP_MASK_ALLOW_INSECURE") != "1" {
		return errors.New("upstream.insecure_skip_verify forbidden (TLS non-negotiable, §6.4); set LDAP_MASK_ALLOW_INSECURE=1 to override")
	}

	if len(c.Mappings) == 0 {
		return errors.New("mappings: at least one mapping is required")
	}

	seen := make(map[string]int, len(c.Mappings))
	for i, m := range c.Mappings {
		if strings.TrimSpace(m.LocalDN) == "" {
			return fmt.Errorf("mapping %d: empty local_dn", i)
		}
		if _, err := bcrypt.Cost([]byte(m.LocalPasswordBcrypt)); err != nil {
			return fmt.Errorf("mapping %d (local_dn %q): local_password_bcrypt is not a valid bcrypt hash: %w", i, m.LocalDN, err)
		}
		if strings.TrimSpace(m.RemoteDN) == "" {
			return fmt.Errorf("mapping %d (local_dn %q): empty remote_dn", i, m.LocalDN)
		}
		if m.RemotePassword == "" {
			return fmt.Errorf("mapping %d (local_dn %q): empty remote_password", i, m.LocalDN)
		}

		key := NormalizeDN(m.LocalDN)
		if prev, dup := seen[key]; dup {
			return fmt.Errorf("mappings: local_dn %q duplicated (entries %d and %d)", m.LocalDN, prev, i)
		}
		seen[key] = i
	}
	return nil
}
