package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// flagsFlagSet parses args against the real configuration FlagSet, exactly as
// run() does.
func flagsFlagSet(t *testing.T, args ...string) (*flag.FlagSet, *flagConfig) {
	t.Helper()
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fc := registerFlags(fs)
	if err := fs.Parse(args); err != nil {
		t.Fatalf("parsing %q: %v", args, err)
	}
	return fs, fc
}

// flagsBcryptHash returns a valid bcrypt hash of "hunter2", for tests that need
// a well-formed local_password_bcrypt.
func flagsBcryptHash(t *testing.T) string {
	t.Helper()
	hash, err := HashPassword("hunter2")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	return hash
}

// flagsBaseYAML is a complete, valid configuration file used as the starting
// point of the override tests. The listener is cleartext so no certificate is
// needed.
func flagsBaseYAML(t *testing.T) string {
	t.Helper()
	hash := flagsBcryptHash(t)
	return `
listen: "ldap://127.0.0.1:1389"
upstream:
  url: "ldap://ldap.internal:389"
  ca_file: /certs/internal-ca.crt
  insecure_skip_verify: false
mappings:
  - local_dn: "cn=test-admin,dc=test"
    local_password_bcrypt: "` + hash + `"
    remote_dn: "cn=admin,dc=example,dc=com"
    remote_password: "upstream-pw"
allow_unmapped_bind: false
`
}

// TestFlagsMapToConfig checks each flag lands on the right Config field.
func TestFlagsMapToConfig(t *testing.T) {
	base := writeConfig(t, flagsBaseYAML(t))

	tests := []struct {
		name  string
		args  []string
		check func(t *testing.T, c *Config)
	}{
		{
			name: "listen",
			args: []string{"--config", base, "--listen", "ldap://127.0.0.1:1390"},
			check: func(t *testing.T, c *Config) {
				if c.Listen != "ldap://127.0.0.1:1390" {
					t.Errorf("Listen = %q", c.Listen)
				}
			},
		},
		{
			name: "tls-cert and tls-key",
			args: []string{"--config", base, "--tls-cert", "/certs/a.crt", "--tls-key", "/certs/a.key"},
			check: func(t *testing.T, c *Config) {
				if c.TLS.CertFile != "/certs/a.crt" || c.TLS.KeyFile != "/certs/a.key" {
					t.Errorf("TLS = %+v", c.TLS)
				}
			},
		},
		{
			name: "upstream",
			args: []string{"--config", base, "--upstream", "ldap://other.internal:389"},
			check: func(t *testing.T, c *Config) {
				if c.Upstream.URL != "ldap://other.internal:389" {
					t.Errorf("Upstream.URL = %q", c.Upstream.URL)
				}
			},
		},
		{
			name: "upstream-ca",
			args: []string{"--config", base, "--upstream-ca", "/certs/ca.crt"},
			check: func(t *testing.T, c *Config) {
				if c.Upstream.CAFile != "/certs/ca.crt" {
					t.Errorf("Upstream.CAFile = %q", c.Upstream.CAFile)
				}
			},
		},
		{
			name: "insecure-skip-verify",
			args: []string{"--config", base, "--insecure-skip-verify"},
			check: func(t *testing.T, c *Config) {
				if !c.Upstream.InsecureSkipVerify {
					t.Error("Upstream.InsecureSkipVerify = false")
				}
			},
		},
		{
			name: "allow-unmapped-bind",
			args: []string{"--config", base, "--allow-unmapped-bind"},
			check: func(t *testing.T, c *Config) {
				if !c.AllowUnmappedBind {
					t.Error("AllowUnmappedBind = false")
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Only insecure_skip_verify needs the exemption; harmless for the
			// others.
			t.Setenv("LDAP_MASK_ALLOW_INSECURE", "1")
			fs, fc := flagsFlagSet(t, tc.args...)
			cfg, _, err := buildConfig(fs, fc)
			if err != nil {
				t.Fatalf("buildConfig: %v", err)
			}
			tc.check(t, cfg)
		})
	}
}

// TestFlagOverrideKeepsFileValues: a flag overrides its field, and the file's
// other values survive untouched.
func TestFlagOverrideKeepsFileValues(t *testing.T) {
	base := writeConfig(t, flagsBaseYAML(t))
	fs, fc := flagsFlagSet(t, "--config", base, "--listen", "ldap://127.0.0.1:1390")

	cfg, _, err := buildConfig(fs, fc)
	if err != nil {
		t.Fatalf("buildConfig: %v", err)
	}
	if cfg.Listen != "ldap://127.0.0.1:1390" {
		t.Errorf("Listen = %q, want the override", cfg.Listen)
	}
	if cfg.Upstream.URL != "ldap://ldap.internal:389" {
		t.Errorf("Upstream.URL = %q, want the file value", cfg.Upstream.URL)
	}
	if cfg.Upstream.CAFile != "/certs/internal-ca.crt" {
		t.Errorf("Upstream.CAFile = %q, want the file value", cfg.Upstream.CAFile)
	}
	if len(cfg.Mappings) != 1 || cfg.Mappings[0].LocalDN != "cn=test-admin,dc=test" {
		t.Errorf("Mappings = %+v, want the file mapping", cfg.Mappings)
	}
	if cfg.AllowUnmappedBind {
		t.Error("AllowUnmappedBind changed although it was not set")
	}
}

// TestMapReplacesFileMappings: --map is a whole-field override, not an append.
func TestMapReplacesFileMappings(t *testing.T) {
	base := writeConfig(t, flagsBaseYAML(t))
	const other = `{"local_dn":"cn=other,dc=test","local_password":"pw",` +
		`"remote_dn":"cn=admin,dc=example,dc=com","remote_password":"upstream-pw"}`
	fs, fc := flagsFlagSet(t, "--config", base, "--map", other)

	cfg, _, err := buildConfig(fs, fc)
	if err != nil {
		t.Fatalf("buildConfig: %v", err)
	}
	if len(cfg.Mappings) != 1 {
		t.Fatalf("len(Mappings) = %d, want 1 (replaced, not appended)", len(cfg.Mappings))
	}
	if cfg.Mappings[0].LocalDN != "cn=other,dc=test" {
		t.Errorf("LocalDN = %q, want the --map value", cfg.Mappings[0].LocalDN)
	}
	if cfg.Lookup("cn=test-admin,dc=test") != nil {
		t.Error("the file's mapping survived the --map override")
	}
}

// TestMapCleartextLocalPasswordIsHashed: the cleartext local_password is hashed
// at startup, and the resulting bcrypt hash verifies the password through the
// ordinary comparison path.
func TestMapCleartextLocalPasswordIsHashed(t *testing.T) {
	const mapping = `{"local_dn":"cn=test-admin,dc=test","local_password":"hunter2",` +
		`"remote_dn":"cn=admin,dc=example,dc=com","remote_password":"upstream-pw"}`
	fs, fc := flagsFlagSet(t,
		"--listen", "ldap://127.0.0.1:1389",
		"--upstream", "ldap://ldap.internal:389",
		"--map", mapping)

	cfg, _, err := buildConfig(fs, fc)
	if err != nil {
		t.Fatalf("buildConfig: %v", err)
	}
	h := cfg.Mappings[0].LocalPasswordBcrypt
	if h == "hunter2" || h == "" {
		t.Fatalf("LocalPasswordBcrypt = %q, the cleartext password was not hashed", h)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(h), []byte("hunter2")); err != nil {
		t.Errorf("hash does not verify hunter2: %v", err)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(h), []byte("wrong")); err == nil {
		t.Error("hash wrongly verifies another password")
	}
}

// TestFlagsOnlyCleartextNeedsNoTLS: the nominal throwaway-container case — a
// cleartext listener configured entirely from flags, with no certificate, no
// key and no file.
func TestFlagsOnlyCleartextNeedsNoTLS(t *testing.T) {
	const mapping = `{"local_dn":"cn=test-admin,dc=test","local_password":"hunter2",` +
		`"remote_dn":"cn=admin,dc=example,dc=com","remote_password":"upstream-pw"}`
	fs, fc := flagsFlagSet(t,
		"--listen", "ldap://0.0.0.0:1389",
		"--upstream", "ldap://127.0.0.1:389",
		"--map", mapping)

	cfg, _, err := buildConfig(fs, fc)
	if err != nil {
		t.Fatalf("flags-only cleartext run refused: %v", err)
	}
	if cfg.TLS.CertFile != "" || cfg.TLS.KeyFile != "" {
		t.Errorf("TLS material set without being asked: %+v", cfg.TLS)
	}
	if scheme, err := cfg.ListenScheme(); err != nil || scheme != "ldap" {
		t.Errorf("listener scheme = %q, %v; want a cleartext listener", scheme, err)
	}
}

// TestMapErrors covers the rejection of malformed --map values.
func TestMapErrors(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{
			name:  "invalid JSON",
			value: `not json`,
			want:  "invalid JSON",
		},
		{
			name: "unknown key",
			value: `{"local_dn":"cn=a,dc=t","local_password":"pw","remote_dn":"cn=b,dc=e",` +
				`"remote_password":"up","bogus":1}`,
			want: "unknown field",
		},
		{
			name: "both password forms",
			value: `{"local_dn":"cn=a,dc=t","local_password":"pw",` +
				`"local_password_bcrypt":"$2a$10$abcdefghijklmnopqrstuv",` +
				`"remote_dn":"cn=b,dc=e","remote_password":"up"}`,
			want: "mutually exclusive",
		},
		{
			name: "neither password form",
			value: `{"local_dn":"cn=a,dc=t","remote_dn":"cn=b,dc=e",` +
				`"remote_password":"up"}`,
			want: "exactly one",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fs, fc := flagsFlagSet(t, "--map", tc.value)
			_, _, err := buildConfig(fs, fc)
			if err == nil {
				t.Fatalf("--map %s accepted", tc.value)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to contain %q", err, tc.want)
			}
		})
	}
}

// TestNoConfigurationError: with neither a file nor a flag, the error must name
// both ways to configure rather than fail downstream.
func TestNoConfigurationError(t *testing.T) {
	fs, fc := flagsFlagSet(t)
	_, _, err := buildConfig(fs, fc)
	if err == nil {
		t.Fatal("an empty command line was accepted")
	}
	for _, want := range []string{"--config", "--listen"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %q, want it to name %q", err, want)
		}
	}
}

// TestConfigDashReadsStdin: "--config -" reads the configuration from standard
// input.
func TestConfigDashReadsStdin(t *testing.T) {
	path := writeConfig(t, flagsBaseYAML(t))
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("opening the config: %v", err)
	}
	defer func() { _ = f.Close() }()

	old := os.Stdin
	os.Stdin = f
	defer func() { os.Stdin = old }()

	fs, fc := flagsFlagSet(t, "--config", "-")
	cfg, _, err := buildConfig(fs, fc)
	if err != nil {
		t.Fatalf("buildConfig from stdin: %v", err)
	}
	if cfg.Upstream.URL != "ldap://ldap.internal:389" {
		t.Errorf("Upstream.URL = %q, want the value read on stdin", cfg.Upstream.URL)
	}
}

// TestExplicitFalseOverridesFileTrue is the case a naive zero-value check gets
// wrong: --insecure-skip-verify=false set explicitly must beat
// insecure_skip_verify: true in the file.
func TestExplicitFalseOverridesFileTrue(t *testing.T) {
	_ = os.Unsetenv("LDAP_MASK_ALLOW_INSECURE")
	body := strings.Replace(flagsBaseYAML(t),
		"insecure_skip_verify: false", "insecure_skip_verify: true", 1)
	base := writeConfig(t, body)

	// Without the override, the file's true is refused (no exemption).
	fs, fc := flagsFlagSet(t, "--config", base)
	if _, _, err := buildConfig(fs, fc); err == nil {
		t.Fatal("insecure_skip_verify: true accepted without an exemption")
	}

	// The explicit false wins.
	fs, fc = flagsFlagSet(t, "--config", base, "--insecure-skip-verify=false")
	cfg, _, err := buildConfig(fs, fc)
	if err != nil {
		t.Fatalf("explicit false refused: %v", err)
	}
	if cfg.Upstream.InsecureSkipVerify {
		t.Error("the file's true won over the explicit --insecure-skip-verify=false")
	}
}

// TestMapErrorsDoNotLeakPasswords: the offending --map is identified by position,
// never by echoing its value. Standard error is kept in CI logs and in
// "docker logs" far longer and far more visibly than the process list, so a
// password echoed here would outlive the argv exposure this mode already
// accepts on purpose.
func TestMapErrorsDoNotLeakPasswords(t *testing.T) {
	const localPw = "LOCAL-SECRET-9f3a"
	const remotePw = "REMOTE-SECRET-4c71"

	values := []string{
		// Above all the error paths that can fire once the object is decoded.
		`{"local_dn":"cn=a,dc=t","local_password":"` + localPw + `","remote_dn":"cn=b,dc=e"}`,
		`{"local_dn":"cn=a,dc=t","local_password":"` + localPw + `","local_password_bcrypt":"x","remote_dn":"cn=b,dc=e","remote_password":"` + remotePw + `"}`,
		`{"local_dn":"cn=a,dc=t","remote_dn":"cn=b,dc=e","remote_password":"` + remotePw + `","bogus":1}`,
		`{"local_dn":"cn=a,dc=t","local_password":"","remote_dn":"cn=b,dc=e","remote_password":"` + remotePw + `"}`,
		`{`, // syntax error: nothing decoded, so only the position can be named
	}

	for i, v := range values {
		fs, fc := flagsFlagSet(t, "--map", v)
		_, _, err := buildConfig(fs, fc)
		if err == nil {
			t.Fatalf("case %d: accepted, an error was expected", i+1)
		}
		if strings.Contains(err.Error(), localPw) || strings.Contains(err.Error(), remotePw) {
			t.Errorf("case %d: the error echoes a password: %v", i+1, err)
		}
		if !strings.Contains(err.Error(), "--map #1") {
			t.Errorf("case %d: the error does not name the offending --map: %v", i+1, err)
		}
	}
}

// TestInsecureSkipVerifyFlagNeedsNoExemption: the environment-variable guard
// targets the FILE form only. A flag typed on a command line is a deliberate act
// every single time, unlike `insecure_skip_verify: true` inherited by copying a
// colleague's YAML — which is the accident the guard exists to prevent.
func TestInsecureSkipVerifyFlagNeedsNoExemption(t *testing.T) {
	_ = os.Unsetenv("LDAP_MASK_ALLOW_INSECURE")

	t.Run("flag alone", func(t *testing.T) {
		fs, fc := flagsFlagSet(t,
			"--listen", "ldap://127.0.0.1:1389",
			"--upstream", "ldaps://directory.internal:636",
			"--insecure-skip-verify",
			"--map", `{"local_dn":"cn=a,dc=t","local_password":"pw","remote_dn":"cn=b,dc=e","remote_password":"up"}`)
		cfg, _, err := buildConfig(fs, fc)
		if err != nil {
			t.Fatalf("--insecure-skip-verify refused without %s: %v", allowInsecureEnv, err)
		}
		if !cfg.Upstream.InsecureSkipVerify {
			t.Error("the flag did not reach the configuration")
		}
	})

	t.Run("flag overrides a file carrying true", func(t *testing.T) {
		body := strings.Replace(flagsBaseYAML(t),
			"insecure_skip_verify: false", "insecure_skip_verify: true", 1)
		fs, fc := flagsFlagSet(t, "--config", writeConfig(t, body), "--insecure-skip-verify")
		cfg, _, err := buildConfig(fs, fc)
		if err != nil {
			t.Fatalf("refused although the flag was given: %v", err)
		}
		if !cfg.Upstream.InsecureSkipVerify {
			t.Error("insecure_skip_verify was lost")
		}
	})

	t.Run("the file still needs the exemption", func(t *testing.T) {
		body := strings.Replace(flagsBaseYAML(t),
			"insecure_skip_verify: false", "insecure_skip_verify: true", 1)
		fs, fc := flagsFlagSet(t, "--config", writeConfig(t, body))
		if _, _, err := buildConfig(fs, fc); err == nil {
			t.Fatalf("the file's true was accepted without %s", allowInsecureEnv)
		}
	})
}

// TestMapEnvExpansion: ${VAR} in a --map's remote_dn and remote_password is
// expanded exactly as in the file form.
func TestMapEnvExpansion(t *testing.T) {
	t.Setenv("LDAP_ADMIN_DN", "cn=admin,dc=example,dc=com")
	t.Setenv("LDAP_ADMIN_PASSWORD", "hunter2-upstream")

	mapping := fmt.Sprintf(`{"local_dn":"cn=test-admin,dc=test","local_password_bcrypt":%q,`+
		`"remote_dn":"${LDAP_ADMIN_DN}","remote_password":"${LDAP_ADMIN_PASSWORD}"}`, flagsBcryptHash(t))
	fs, fc := flagsFlagSet(t,
		"--listen", "ldap://127.0.0.1:1389",
		"--upstream", "ldap://ldap.internal:389",
		"--map", mapping)

	cfg, _, err := buildConfig(fs, fc)
	if err != nil {
		t.Fatalf("buildConfig: %v", err)
	}
	if cfg.Mappings[0].RemoteDN != "cn=admin,dc=example,dc=com" {
		t.Errorf("RemoteDN = %q, want the expanded value", cfg.Mappings[0].RemoteDN)
	}
	if cfg.Mappings[0].RemotePassword != "hunter2-upstream" {
		t.Errorf("RemotePassword = %q, want the expanded value", cfg.Mappings[0].RemotePassword)
	}
}

// TestMapEnvExpansionMissingVariable: a ${VAR} referenced in --map but absent
// from the environment fails startup, and the error never echoes the password.
func TestMapEnvExpansionMissingVariable(t *testing.T) {
	const remotePw = "REMOTE-SECRET-9a1c"
	value := fmt.Sprintf(`{"local_dn":"cn=a,dc=t","local_password_bcrypt":%q,`+
		`"remote_dn":"cn=b,dc=e","remote_password":"${LDAP_MASK_TEST_UNDEFINED_VAR}"}`, flagsBcryptHash(t))
	fs, fc := flagsFlagSet(t, "--map", value)
	_, _, err := buildConfig(fs, fc)
	if err == nil {
		t.Fatal("a missing ${VAR} was accepted")
	}
	if !strings.Contains(err.Error(), "LDAP_MASK_TEST_UNDEFINED_VAR") {
		t.Errorf("error = %q, want it to name the missing variable", err)
	}
	if strings.Contains(err.Error(), remotePw) {
		t.Errorf("error = %q, echoes a password", err)
	}
}

// TestMapLiteralPasswordWarning covers when buildConfig reports a password
// having arrived literally on the command line: the case the startup WARN must
// fire for.
func TestMapLiteralPasswordWarning(t *testing.T) {
	t.Setenv("LDAP_ADMIN_PASSWORD", "hunter2-upstream")
	hash := flagsBcryptHash(t)

	tests := []struct {
		name string
		args []string
		want bool
	}{
		{
			name: "bcrypt local password and ${VAR} remote password",
			args: []string{"--map", fmt.Sprintf(`{"local_dn":"cn=test-admin,dc=test","local_password_bcrypt":%q,`+
				`"remote_dn":"cn=admin,dc=example,dc=com","remote_password":"${LDAP_ADMIN_PASSWORD}"}`, hash)},
			want: false,
		},
		{
			name: "literal remote password",
			args: []string{"--map", fmt.Sprintf(`{"local_dn":"cn=test-admin,dc=test","local_password_bcrypt":%q,`+
				`"remote_dn":"cn=admin,dc=example,dc=com","remote_password":"hunter2-upstream"}`, hash)},
			want: true,
		},
		{
			name: "cleartext local password",
			args: []string{"--map", `{"local_dn":"cn=test-admin,dc=test","local_password":"hunter2",` +
				`"remote_dn":"cn=admin,dc=example,dc=com","remote_password":"${LDAP_ADMIN_PASSWORD}"}`},
			want: true,
		},
		{
			name: "remote password mixing a literal prefix and ${VAR}",
			args: []string{"--map", fmt.Sprintf(`{"local_dn":"cn=test-admin,dc=test","local_password_bcrypt":%q,`+
				`"remote_dn":"cn=admin,dc=example,dc=com","remote_password":"prefix${LDAP_ADMIN_PASSWORD}"}`, hash)},
			want: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string{"--listen", "ldap://127.0.0.1:1389", "--upstream", "ldap://ldap.internal:389"}, tc.args...)
			fs, fc := flagsFlagSet(t, args...)
			_, literal, err := buildConfig(fs, fc)
			if err != nil {
				t.Fatalf("buildConfig: %v", err)
			}
			if literal != tc.want {
				t.Errorf("literalPassword = %v, want %v", literal, tc.want)
			}
		})
	}
}

// TestMappingFlags: --local-dn and its companions describe one mapping without
// --map's JSON, validated and hashed exactly like a --map entry.
func TestMappingFlags(t *testing.T) {
	t.Setenv("LDAP_ADMIN_PASSWORD", "hunter2-upstream")
	base := writeConfig(t, flagsBaseYAML(t))

	fs, fc := flagsFlagSet(t,
		"--config", base,
		"--local-dn", "cn=other,dc=test",
		"--local-password", "hunter2",
		"--remote-dn", "cn=admin,dc=example,dc=com",
		"--remote-password", "${LDAP_ADMIN_PASSWORD}")

	cfg, literal, err := buildConfig(fs, fc)
	if err != nil {
		t.Fatalf("buildConfig: %v", err)
	}
	if len(cfg.Mappings) != 1 || cfg.Mappings[0].LocalDN != "cn=other,dc=test" {
		t.Fatalf("Mappings = %+v, want only the flag mapping (file list replaced)", cfg.Mappings)
	}
	m := cfg.Mappings[0]
	if err := bcrypt.CompareHashAndPassword([]byte(m.LocalPasswordBcrypt), []byte("hunter2")); err != nil {
		t.Errorf("hash does not verify hunter2: %v", err)
	}
	if m.RemotePassword != "hunter2-upstream" {
		t.Errorf("RemotePassword = %q, want the expanded value", m.RemotePassword)
	}
	if !literal {
		t.Error("literalPassword = false with a cleartext --local-password")
	}
}

// TestMappingFlagsWithMap: the flag mapping is added to the --map ones.
func TestMappingFlagsWithMap(t *testing.T) {
	fs, fc := flagsFlagSet(t,
		"--map", fmt.Sprintf(`{"local_dn":"cn=a,dc=t","local_password_bcrypt":%q,`+
			`"remote_dn":"cn=admin,dc=example,dc=com","remote_password":"up"}`, flagsBcryptHash(t)),
		"--local-dn", "cn=b,dc=t",
		"--local-password-bcrypt", flagsBcryptHash(t),
		"--remote-dn", "cn=admin,dc=example,dc=com",
		"--remote-password", "up",
		"--listen", "ldap://127.0.0.1:1389",
		"--upstream", "ldap://ldap.internal:389")

	cfg, _, err := buildConfig(fs, fc)
	if err != nil {
		t.Fatalf("buildConfig: %v", err)
	}
	if cfg.Lookup("cn=a,dc=t") == nil || cfg.Lookup("cn=b,dc=t") == nil {
		t.Errorf("Mappings = %+v, want both the --map and the flag mapping", cfg.Mappings)
	}
}

// TestMappingFlagsErrors: an incomplete or contradictory flag mapping is
// refused, and the error names the flag rather than the JSON key.
func TestMappingFlagsErrors(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "missing remote password",
			args: []string{"--local-dn", "cn=a,dc=t", "--local-password", "pw", "--remote-dn", "cn=b,dc=e"},
			want: "--remote-password is required",
		},
		{
			name: "remote DN alone",
			args: []string{"--remote-dn", "cn=b,dc=e"},
			want: "--local-dn is required",
		},
		{
			name: "both password forms",
			args: []string{"--local-dn", "cn=a,dc=t", "--local-password", "pw",
				"--local-password-bcrypt", "$2a$10$abcdefghijklmnopqrstuv",
				"--remote-dn", "cn=b,dc=e", "--remote-password", "up"},
			want: "--local-password and --local-password-bcrypt are mutually exclusive",
		},
		{
			name: "empty local password",
			args: []string{"--local-dn", "cn=a,dc=t", "--local-password", "",
				"--remote-dn", "cn=b,dc=e", "--remote-password", "up"},
			want: "--local-password is empty",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fs, fc := flagsFlagSet(t, tc.args...)
			_, _, err := buildConfig(fs, fc)
			if err == nil {
				t.Fatalf("%q accepted", tc.args)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to contain %q", err, tc.want)
			}
		})
	}
}
