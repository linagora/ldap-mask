package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNormalizeDN(t *testing.T) {
	cases := map[string]string{
		"CN=Test-Admin, DC=Test":         "cn=test-admin,dc=test",
		"cn=admin , dc=example , dc=com": "cn=admin,dc=example,dc=com",
		"  CN=A,DC=B  ":                  "cn=a,dc=b",
		"cn=x,dc=test":                   "cn=x,dc=test",
	}
	for in, want := range cases {
		if got := NormalizeDN(in); got != want {
			t.Errorf("NormalizeDN(%q) = %q, want %q", in, got, want)
		}
	}
}

// writeConfig writes a config to a temporary file.
func writeConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}
	return path
}

func validConfigYAML(hash string) string {
	return `
listen: "ldaps://0.0.0.0:1636"
tls:
  cert_file: /certs/proxy.crt
  key_file:  /certs/proxy.key
upstream:
  url: "ldaps://ldap.internal:636"
  ca_file: /certs/internal-ca.crt
  insecure_skip_verify: false
mappings:
  - local_dn: "cn=test-admin,dc=test"
    local_password_bcrypt: "` + hash + `"
    remote_dn: "cn=admin,dc=example,dc=com"
    remote_password: "${TEST_REMOTE_PW}"
allow_unmapped_bind: false
`
}

func TestLoadExpandsEnvAndLookup(t *testing.T) {
	hash, err := HashPassword("hunter2")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	t.Setenv("TEST_REMOTE_PW", "s3cret-upstream")

	path := writeConfig(t, validConfigYAML(hash))
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Mappings[0].RemotePassword != "s3cret-upstream" {
		t.Errorf("remote_password = %q, want expansion of ${TEST_REMOTE_PW}", cfg.Mappings[0].RemotePassword)
	}

	// Lookup tolerates case and spaces around commas.
	m := cfg.Lookup("CN=Test-Admin , DC=Test")
	if m == nil {
		t.Fatal("Lookup did not find the mapping (normalization)")
	}
	if m.RemoteDN != "cn=admin,dc=example,dc=com" {
		t.Errorf("remote_dn = %q", m.RemoteDN)
	}
	if cfg.Lookup("cn=unknown,dc=test") != nil {
		t.Error("Lookup found a non-existent mapping")
	}
}

func TestLoadUnsetEnvFails(t *testing.T) {
	hash, err := HashPassword("hunter2")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	// We make sure the variable does not exist.
	_ = os.Unsetenv("TEST_REMOTE_PW")

	path := writeConfig(t, validConfigYAML(hash))
	_, err = Load(path)
	if err == nil {
		t.Fatal("Load accepted an undefined environment variable")
	}
	if !strings.Contains(err.Error(), "TEST_REMOTE_PW") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestLoadRejectsBadBcrypt(t *testing.T) {
	t.Setenv("TEST_REMOTE_PW", "whatever")
	path := writeConfig(t, validConfigYAML("not-a-bcrypt-hash"))
	_, err := Load(path)
	if err == nil {
		t.Fatal("Load accepted an invalid bcrypt hash")
	}
	if !strings.Contains(err.Error(), "bcrypt") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestLoadRejectsMissingMappings(t *testing.T) {
	body := `
listen: "ldaps://0.0.0.0:1636"
tls:
  cert_file: a
  key_file: b
upstream:
  url: "ldap://ldap.internal:389"
mappings: []
`
	_, err := Load(writeConfig(t, body))
	if err == nil {
		t.Fatal("Load accepted a configuration without mapping")
	}
}

func TestValidateInsecureSkipVerify(t *testing.T) {
	hash, err := HashPassword("x")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	body := `
listen: "ldaps://0.0.0.0:1636"
tls:
  cert_file: a
  key_file: b
upstream:
  url: "ldaps://ldap.internal:636"
  insecure_skip_verify: true
mappings:
  - local_dn: "cn=a,dc=t"
    local_password_bcrypt: "` + hash + `"
    remote_dn: "cn=admin,dc=e"
    remote_password: "pw"
`
	_ = os.Unsetenv("LDAP_MASK_ALLOW_INSECURE")
	if _, err := Load(writeConfig(t, body)); err == nil {
		t.Fatal("insecure_skip_verify accepted without exemption")
	}

	t.Setenv("LDAP_MASK_ALLOW_INSECURE", "1")
	if _, err := Load(writeConfig(t, body)); err != nil {
		t.Fatalf("insecure_skip_verify refused despite the exemption: %v", err)
	}
}

func TestValidateDuplicateLocalDN(t *testing.T) {
	hash, err := HashPassword("x")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	body := `
listen: "ldaps://0.0.0.0:1636"
tls:
  cert_file: a
  key_file: b
upstream:
  url: "ldap://ldap.internal:389"
mappings:
  - local_dn: "cn=a,dc=t"
    local_password_bcrypt: "` + hash + `"
    remote_dn: "cn=x,dc=e"
    remote_password: "pw"
  - local_dn: "CN=A , DC=T"
    local_password_bcrypt: "` + hash + `"
    remote_dn: "cn=y,dc=e"
    remote_password: "pw2"
`
	if _, err := Load(writeConfig(t, body)); err == nil {
		t.Fatal("duplicated (normalized) local DN wrongly accepted")
	}
}

// TestListenSchemeAndAddr covers the reading of the listener scheme.
//
// The scheme is MANDATORY: without it, nothing distinguishes a cleartext
// listener from a TLS listener, and a misreading would serve in cleartext a
// proxy believed to be encrypted. We therefore refuse rather than guess.
func TestListenSchemeAndAddr(t *testing.T) {
	tests := []struct {
		name       string
		listen     string
		wantScheme string // "" = the scheme itself must be refused
		wantAddr   string
		// wantAddrErr: the scheme is valid but the address must be refused.
		wantAddrErr bool
	}{
		{name: "ldaps with port", listen: "ldaps://0.0.0.0:1636", wantScheme: "ldaps", wantAddr: "0.0.0.0:1636"},
		{name: "ldap with port", listen: "ldap://0.0.0.0:1389", wantScheme: "ldap", wantAddr: "0.0.0.0:1389"},
		{name: "ldaps without port", listen: "ldaps://proxy.example.org", wantScheme: "ldaps", wantAddr: "proxy.example.org:636"},
		{name: "ldap without port", listen: "ldap://proxy.example.org", wantScheme: "ldap", wantAddr: "proxy.example.org:389"},
		{name: "ipv6 without port", listen: "ldaps://[::1]", wantScheme: "ldaps", wantAddr: "[::1]:636"},
		{name: "ipv6 with port", listen: "ldaps://[::]:1636", wantScheme: "ldaps", wantAddr: "[::]:1636"},
		{name: "uppercase scheme", listen: "LDAPS://host:1636", wantScheme: "ldaps", wantAddr: "host:1636"},
		{name: "trailing slash", listen: "ldaps://host:636/", wantScheme: "ldaps", wantAddr: "host:636"},
		// Port 0 = "take a free port": legitimate, especially for tests.
		{name: "ephemeral port", listen: "ldap://127.0.0.1:0", wantScheme: "ldap", wantAddr: "127.0.0.1:0"},

		{name: "address alone, without scheme", listen: "0.0.0.0:1636"},
		{name: "name alone, without scheme", listen: "proxy.example.org:1636"},
		{name: "unknown scheme", listen: "http://0.0.0.0:1636"},
		{name: "empty", listen: ""},
		{name: "non-numeric port", listen: "ldaps://host:abc"},
		{name: "trailing space", listen: "ldaps://host:1636 "},

		// Valid scheme, refused address.
		{name: "empty host", listen: "ldaps://:1636", wantScheme: "ldaps", wantAddrErr: true},
		{name: "port out of range", listen: "ldaps://host:99999", wantScheme: "ldaps", wantAddrErr: true},
		// A userinfo would otherwise be ignored… after having been logged raw at
		// startup: exactly the leak we fix on the upstream side.
		{name: "userinfo", listen: "ldaps://cn=admin:pw@host:636", wantScheme: "ldaps", wantAddrErr: true},
		{name: "path", listen: "ldaps://host:636/path", wantScheme: "ldaps", wantAddrErr: true},

		// Unbracketed IPv6: url.Parse splits it at the wrong colon and would
		// hand back an address net.Listen refuses ("missing port in address" /
		// "too many colons"). The message must ask for brackets instead of
		// letting the bind failure speak.
		{name: "unbracketed ipv6, no port", listen: "ldaps://::1", wantScheme: "ldaps", wantAddrErr: true},
		{name: "unbracketed ipv6, with port", listen: "ldaps://::1:636", wantScheme: "ldaps", wantAddrErr: true},
		{name: "unbracketed link-local ipv6", listen: "ldaps://fe80::1", wantScheme: "ldaps", wantAddrErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := &Config{Listen: tc.listen}

			scheme, err := c.ListenScheme()
			if tc.wantScheme == "" {
				if err == nil {
					t.Fatalf("ListenScheme(%q) = %q, an error was expected", tc.listen, scheme)
				}
				if _, err := c.ListenAddr(); err == nil {
					t.Fatalf("ListenAddr(%q) accepted a listener without a usable scheme", tc.listen)
				}
				return
			}
			if err != nil {
				t.Fatalf("ListenScheme(%q): %v", tc.listen, err)
			}
			if scheme != tc.wantScheme {
				t.Errorf("scheme = %q, want %q", scheme, tc.wantScheme)
			}

			addr, err := c.ListenAddr()
			if tc.wantAddrErr {
				if err == nil {
					t.Fatalf("ListenAddr(%q) = %q, an error was expected", tc.listen, addr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ListenAddr(%q): %v", tc.listen, err)
			}
			if addr != tc.wantAddr {
				t.Errorf("address = %q, want %q", addr, tc.wantAddr)
			}
		})
	}
}

// TestValidateTLSCertRequiredOnlyForLDAPS checks that the certificate is
// required only for a TLS listener: a debug tool must be able to serve in
// cleartext without having to craft a certificate.
func TestValidateTLSCertRequiredOnlyForLDAPS(t *testing.T) {
	hash, err := HashPassword("x")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	body := func(listen string) string {
		return `
listen: "` + listen + `"
upstream:
  url: "ldap://ldap.internal:389"
mappings:
  - local_dn: "cn=a,dc=t"
    local_password_bcrypt: "` + hash + `"
    remote_dn: "cn=x,dc=e"
    remote_password: "pw"
`
	}

	if _, err := Load(writeConfig(t, body("ldaps://0.0.0.0:1636"))); err == nil {
		t.Error("ldaps:// listener accepted without a certificate")
	}
	if _, err := Load(writeConfig(t, body("ldap://0.0.0.0:1389"))); err != nil {
		t.Errorf("ldap:// listener refused without a certificate: %v", err)
	}
	if _, err := Load(writeConfig(t, body("0.0.0.0:1636"))); err == nil {
		t.Error("listener without a scheme accepted")
	}
}

// TestValidateRejectsUpstreamUserinfo: the upstream credentials are declared in
// the mappings. A userinfo in upstream.url would be ignored silently — after
// having forced writing the real password in cleartext on disk (§6.2).
func TestValidateRejectsUpstreamUserinfo(t *testing.T) {
	hash, err := HashPassword("x")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	body := `
listen: "ldaps://0.0.0.0:1636"
tls:
  cert_file: a
  key_file: b
upstream:
  url: "ldaps://cn=admin:password@ldap.internal:636"
mappings:
  - local_dn: "cn=a,dc=t"
    local_password_bcrypt: "` + hash + `"
    remote_dn: "cn=x,dc=e"
    remote_password: "pw"
`
	if _, err := Load(writeConfig(t, body)); err == nil {
		t.Error("userinfo accepted in upstream.url")
	}
}

func TestValidateBadUpstreamURL(t *testing.T) {
	hash, err := HashPassword("x")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	body := `
listen: "ldaps://0.0.0.0:1636"
tls:
  cert_file: a
  key_file: b
upstream:
  url: "http://ldap.internal"
mappings:
  - local_dn: "cn=a,dc=t"
    local_password_bcrypt: "` + hash + `"
    remote_dn: "cn=x,dc=e"
    remote_password: "pw"
`
	if _, err := Load(writeConfig(t, body)); err == nil {
		t.Fatal("invalid upstream URL scheme wrongly accepted")
	}
}
