//go:build e2e

// e2e_test.go — integration tests against a real OpenLDAP directory.
//
// They run only if LDAP_MASK_E2E=1, so that `go test ./...` (the "test" job of
// ci.yml) stays green without a directory. The CI runs them via:
//
//	go test -tags=e2e -v ./...
//
// Expected variables (see .github/workflows/e2e.yml):
//
//	LDAP_MASK_E2E              set to "1" to enable
//	LDAP_E2E_UPSTREAM_URL       e.g. ldap://localhost:389 or ldaps://…
//	LDAP_E2E_REMOTE_DN          real DN on the upstream
//	LDAP_E2E_REMOTE_PASSWORD    real password on the upstream
//	LDAP_E2E_BASE_DN            directory suffix
//	LDAP_E2E_CERT_DIR           where to drop the proxy's certificate
//
// The verifications go through the OpenLDAP clients (ldapwhoami, ldapsearch),
// that is to say through real BER encoders: that is the whole point of the
// test.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	e2eLocalDN   = "cn=test-admin,dc=test"
	e2eLocalPass = "hunter2-e2e"
)

// e2eSetup groups the upstream directory, the started proxy and what is needed
// to query it.
type e2eSetup struct {
	proxyURL string
	caFile   string
}

// requireE2E skips the test if the environment is not armed, and checks that
// the LDAP clients are available.
func requireE2E(t *testing.T) {
	t.Helper()
	if os.Getenv("LDAP_MASK_E2E") != "1" {
		t.Skip("LDAP_MASK_E2E != 1: integration test skipped")
	}
	for _, bin := range []string{"ldapwhoami", "ldapsearch"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not found: install ldap-utils", bin)
		}
	}
}

// startE2E starts the proxy with a TLS listener and a cleartext upstream: this
// is the CI's default configuration.
func startE2E(t *testing.T) *e2eSetup {
	t.Helper()
	return startE2EWith(t, "ldaps", os.Getenv("LDAP_E2E_UPSTREAM_URL"), false)
}

// startE2EWith writes a configuration, starts the proxy and returns what is
// needed to query it.
//
// listenScheme is "ldap" (cleartext) or "ldaps" (TLS). upstreamInsecure allows
// disabling verification of the upstream certificate — reserved for TLS
// upstreams whose CA we do not want to install in a test.
func startE2EWith(t *testing.T, listenScheme, upstream string, upstreamInsecure bool) *e2eSetup {
	t.Helper()

	remoteDN := os.Getenv("LDAP_E2E_REMOTE_DN")
	remotePw := os.Getenv("LDAP_E2E_REMOTE_PASSWORD")
	baseDN := os.Getenv("LDAP_E2E_BASE_DN")
	certDir := os.Getenv("LDAP_E2E_CERT_DIR")
	if certDir == "" {
		certDir = t.TempDir()
	}
	if err := os.MkdirAll(certDir, 0o755); err != nil {
		t.Fatalf("creating %s: %v", certDir, err)
	}
	for name, v := range map[string]string{
		"LDAP_E2E_UPSTREAM_URL":    upstream,
		"LDAP_E2E_REMOTE_DN":       remoteDN,
		"LDAP_E2E_REMOTE_PASSWORD": remotePw,
		"LDAP_E2E_BASE_DN":         baseDN,
	} {
		if v == "" {
			t.Fatalf("%s not defined", name)
		}
	}

	certPath := selfSignedCert(t, certDir)

	hash, err := HashPassword(e2eLocalPass)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	// The upstream password is injected via ${VAR}, never in cleartext (design §5).
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	cfgYAML := fmt.Sprintf(`listen: %q

tls:
  cert_file: %s
  key_file:  %s

upstream:
  url: %q
  insecure_skip_verify: %t

mappings:
  - local_dn: %q
    local_password_bcrypt: %q
    remote_dn: %q
    remote_password: "${LDAP_E2E_REMOTE_PASSWORD}"

allow_unmapped_bind: false
`, listenScheme+"://127.0.0.1:0", certPath, filepath.Join(certDir, "key.pem"),
		upstream, upstreamInsecure, e2eLocalDN, hash, remoteDN)
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o600); err != nil {
		t.Fatalf("writing the configuration: %v", err)
	}
	if upstreamInsecure {
		// Config.Validate refuses insecure_skip_verify without this exemption.
		t.Setenv("LDAP_MASK_ALLOW_INSECURE", "1")
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	p, err := New(cfg, logger)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// We go through listenFor: it is the same path as main(), so the listener
	// scheme is genuinely exercised, TLS as well as cleartext.
	ln, err := listenFor(cfg)
	if err != nil {
		t.Fatalf("listenFor: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = p.Serve(ctx, ln)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	return &e2eSetup{
		// 127.0.0.1 and not "localhost": on some machines localhost resolves
		// only to ::1 whereas the listener is on 127.0.0.1.
		proxyURL: listenScheme + "://" + ln.Addr().String(),
		caFile:   certPath,
	}
}

// ldapCmd runs an OpenLDAP client against the proxy and returns the combined
// output as well as the exit code.
func (s *e2eSetup) ldapCmd(t *testing.T, bin string, args ...string) (string, int) {
	t.Helper()
	return s.ldapCmdEnv(t, nil, bin, args...)
}

// TestE2EBindVerifications covers the DESIGN.md §9 test plan, points 1 to 5.
func TestE2EBindVerifications(t *testing.T) {
	requireE2E(t)
	s := startE2E(t)
	baseDN := os.Getenv("LDAP_E2E_BASE_DN")
	realPw := os.Getenv("LDAP_E2E_REMOTE_PASSWORD")
	realDN := os.Getenv("LDAP_E2E_REMOTE_DN")

	t.Run("1_bind_local_accepted_and_reveals_real_dn", func(t *testing.T) {
		out, rc := s.ldapCmd(t, "ldapwhoami", "-x", "-H", s.proxyURL, "-D", e2eLocalDN, "-w", e2eLocalPass)
		if rc != 0 {
			t.Fatalf("local bind refused (rc=%d):\n%s", rc, out)
		}
		// WhoAmI returns the real DN: this is the documented §6.3 leak, and it
		// proves here that the substitution did take place.
		if !strings.Contains(strings.ToLower(out), strings.ToLower(realDN)) {
			t.Errorf("the real DN %q does not appear in the response:\n%s", realDN, out)
		}
	})

	t.Run("2_search_relayed", func(t *testing.T) {
		out, rc := s.ldapCmd(t, "ldapsearch", "-x", "-LLL", "-H", s.proxyURL,
			"-D", e2eLocalDN, "-w", e2eLocalPass, "-b", baseDN, "-s", "base",
			"(objectclass=*)", "dn")
		if rc != 0 {
			t.Fatalf("search refused (rc=%d):\n%s", rc, out)
		}
		if !strings.Contains(out, baseDN) {
			t.Errorf("the suffix %q is absent from the result:\n%s", baseDN, out)
		}
	})

	t.Run("3_wrong_local_password", func(t *testing.T) {
		out, rc := s.ldapCmd(t, "ldapwhoami", "-x", "-H", s.proxyURL, "-D", e2eLocalDN, "-w", "wrong")
		if rc == 0 {
			t.Fatalf("bind accepted with a wrong password:\n%s", out)
		}
		if !strings.Contains(out, "Invalid credentials") {
			t.Errorf("want \"Invalid credentials\" (49), got:\n%s", out)
		}
	})

	t.Run("4_unmapped_dn_indistinguishable", func(t *testing.T) {
		out, rc := s.ldapCmd(t, "ldapwhoami", "-x", "-H", s.proxyURL, "-D", "cn=unknown,dc=test", "-w", e2eLocalPass)
		if rc == 0 {
			t.Fatalf("bind accepted for an unmapped DN:\n%s", out)
		}
		if !strings.Contains(out, "Invalid credentials") {
			t.Errorf("want \"Invalid credentials\" (49), got:\n%s", out)
		}
	})

	t.Run("5_real_password_refused_on_local_dn", func(t *testing.T) {
		out, rc := s.ldapCmd(t, "ldapwhoami", "-x", "-H", s.proxyURL, "-D", e2eLocalDN, "-w", realPw)
		if rc == 0 {
			t.Fatalf("THE REAL PASSWORD IS ACCEPTED ON THE LOCAL DN:\n%s", out)
		}
	})

	t.Run("5b_real_pair_unmapped_refused", func(t *testing.T) {
		out, rc := s.ldapCmd(t, "ldapwhoami", "-x", "-H", s.proxyURL, "-D", realDN, "-w", realPw)
		if rc == 0 {
			t.Fatalf("the real pair is accepted whereas allow_unmapped_bind=false:\n%s", out)
		}
	})
}

// TestE2ECleartextListener checks that the proxy also serves in cleartext LDAP.
//
// It is a debug tool: it must be able to sit on either side of a client or a
// directory, encrypted or not. The four listener x upstream combinations must
// work; this one is "cleartext x cleartext".
func TestE2ECleartextListener(t *testing.T) {
	requireE2E(t)
	s := startE2EWith(t, "ldap", os.Getenv("LDAP_E2E_UPSTREAM_URL"), false)
	if !strings.HasPrefix(s.proxyURL, "ldap://") {
		t.Fatalf("proxy URL = %q, want an ldap:// scheme", s.proxyURL)
	}
	realDN := os.Getenv("LDAP_E2E_REMOTE_DN")

	t.Run("bind_local", func(t *testing.T) {
		out, rc := s.ldapCmd(t, "ldapwhoami", "-x", "-H", s.proxyURL, "-D", e2eLocalDN, "-w", e2eLocalPass)
		if rc != 0 {
			t.Fatalf("local bind refused in cleartext (rc=%d):\n%s", rc, out)
		}
		if !strings.Contains(strings.ToLower(out), strings.ToLower(realDN)) {
			t.Errorf("the real DN %q does not appear in the response:\n%s", realDN, out)
		}
	})

	t.Run("search", func(t *testing.T) {
		out, rc := s.ldapCmd(t, "ldapsearch", "-x", "-LLL", "-H", s.proxyURL,
			"-D", e2eLocalDN, "-w", e2eLocalPass,
			"-b", os.Getenv("LDAP_E2E_BASE_DN"), "-s", "base", "(objectclass=*)", "dn")
		if rc != 0 {
			t.Fatalf("search refused in cleartext (rc=%d):\n%s", rc, out)
		}
		if !strings.Contains(out, os.Getenv("LDAP_E2E_BASE_DN")) {
			t.Errorf("the suffix is absent from the result:\n%s", out)
		}
	})

	t.Run("wrong_password", func(t *testing.T) {
		out, rc := s.ldapCmd(t, "ldapwhoami", "-x", "-H", s.proxyURL, "-D", e2eLocalDN, "-w", "wrong")
		if rc == 0 {
			t.Fatalf("bind accepted with a wrong password:\n%s", out)
		}
		if !strings.Contains(out, "Invalid credentials") {
			t.Errorf("want \"Invalid credentials\" (49), got:\n%s", out)
		}
	})

	t.Run("real_password_is_refused", func(t *testing.T) {
		out, rc := s.ldapCmd(t, "ldapwhoami", "-x", "-H", s.proxyURL,
			"-D", e2eLocalDN, "-w", os.Getenv("LDAP_E2E_REMOTE_PASSWORD"))
		if rc == 0 {
			t.Fatalf("THE REAL PASSWORD IS ACCEPTED ON THE LOCAL DN:\n%s", out)
		}
	})

	// On a cleartext listener, StartTLS is genuinely reachable — which was not
	// the case with a TLS listener. It must be refused cleanly (design §3), and
	// above all the connection must not be promoted to TLS.
	t.Run("starttls_refused", func(t *testing.T) {
		out, rc := s.ldapCmd(t, "ldapwhoami", "-x", "-H", s.proxyURL, "-ZZ",
			"-D", e2eLocalDN, "-w", e2eLocalPass)
		if rc == 0 {
			t.Fatalf("StartTLS wrongly accepted:\n%s", out)
		}
		// OpenLDAP renders code 53 in the form "Server is unwilling to
		// perform", followed by the diagnostic the proxy synthesised.
		if !strings.Contains(strings.ToLower(out), "unwilling to perform") {
			t.Errorf("want \"unwilling to perform\" (53), got:\n%s", out)
		}
		if !strings.Contains(out, "LDAPS") {
			t.Errorf("the proxy's diagnostic is not reported back to the client:\n%s", out)
		}
	})
}

// TestE2EUpstreamTLS covers the combinations whose UPSTREAM is in TLS.
//
// Runs only if LDAP_E2E_UPSTREAM_TLS_URL is provided: the CI starts its
// OpenLDAP container with TLS, but we do not want to make the test depend on an
// installed upstream certificate — hence insecure_skip_verify, which is here an
// accepted test choice (§6.4 forbids it by default, the exemption is explicit).
func TestE2EUpstreamTLS(t *testing.T) {
	requireE2E(t)
	upstream := os.Getenv("LDAP_E2E_UPSTREAM_TLS_URL")
	if upstream == "" {
		t.Skip("LDAP_E2E_UPSTREAM_TLS_URL not defined: TLS upstream not tested")
	}
	realDN := os.Getenv("LDAP_E2E_REMOTE_DN")

	for _, scheme := range []string{"ldap", "ldaps"} {
		t.Run("listener_"+scheme, func(t *testing.T) {
			s := startE2EWith(t, scheme, upstream, true)

			out, rc := s.ldapCmd(t, "ldapwhoami", "-x", "-H", s.proxyURL,
				"-D", e2eLocalDN, "-w", e2eLocalPass)
			if rc != 0 {
				t.Fatalf("bind via a TLS upstream refused (rc=%d):\n%s", rc, out)
			}
			if !strings.Contains(strings.ToLower(out), strings.ToLower(realDN)) {
				t.Errorf("the real DN %q does not appear in the response:\n%s", realDN, out)
			}
		})
	}
}

// TestE2EPagedResultsAndModification covers points 6 onwards: the controls and
// the write operations must cross the proxy intact.
func TestE2EPagedResultsAndModification(t *testing.T) {
	requireE2E(t)
	s := startE2E(t)
	baseDN := os.Getenv("LDAP_E2E_BASE_DN")
	realDN := os.Getenv("LDAP_E2E_REMOTE_DN")
	realPw := os.Getenv("LDAP_E2E_REMOTE_PASSWORD")

	t.Run("6_paged_results", func(t *testing.T) {
		out, rc := s.ldapCmd(t, "ldapsearch", "-x", "-LLL", "-H", s.proxyURL,
			"-D", e2eLocalDN, "-w", e2eLocalPass,
			"-E", "pr=5/noprompt", "-b", baseDN, "(objectclass=*)", "dn")
		if rc != 0 {
			t.Fatalf("paged results refused (rc=%d):\n%s", rc, out)
		}
	})

	t.Run("6d_modification_relayed", func(t *testing.T) {
		probeDN := "cn=probe-e2e," + baseDN
		ldif := fmt.Sprintf("dn: %s\nobjectClass: organizationalRole\ncn: probe-e2e\n", probeDN)

		addOut, rc := s.ldapCmdStdin(t, ldif, "ldapadd", "-x", "-H", s.proxyURL,
			"-D", e2eLocalDN, "-w", e2eLocalPass)
		if rc != 0 {
			t.Fatalf("ldapadd refused (rc=%d):\n%s", rc, addOut)
		}
		t.Cleanup(func() {
			// Cleanup directly on the upstream, with the real account.
			upstream := os.Getenv("LDAP_E2E_UPSTREAM_URL")
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			c := exec.CommandContext(ctx, "ldapdelete", "-x", "-H", upstream,
				"-D", realDN, "-w", realPw, probeDN)
			_ = c.Run()
		})

		// The modification must be visible on the upstream side, directly.
		upstream := os.Getenv("LDAP_E2E_UPSTREAM_URL")
		check, rc := s.ldapCmdEnv(t, nil, "ldapsearch", "-x", "-LLL", "-H", upstream,
			"-D", realDN, "-w", realPw, "-b", probeDN, "-s", "base", "(objectclass=*)", "cn")
		if rc != 0 || !strings.Contains(check, "probe-e2e") {
			t.Fatalf("the entry added via the proxy is absent from the upstream (rc=%d):\n%s", rc, check)
		}
	})
}

// TestE2EStartTLSRefused checks that StartTLS is refused locally
// (unwillingToPerform) and is not forwarded to the upstream (design §3).
//
// We cannot do it with ldapwhoami: the proxy's listener is TLS, so a StartTLS
// request is reachable only after a TLS handshake — we therefore speak BER
// directly, which is also more precise.
func TestE2EStartTLSRefused(t *testing.T) {
	requireE2E(t)
	s := startE2E(t)

	addr := strings.TrimPrefix(s.proxyURL, "ldaps://")
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		RootCAs:    caPool(t, s.caFile),
		ServerName: "127.0.0.1",
		MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("TLS connection to the proxy: %v", err)
	}
	defer conn.Close()

	// ExtendedRequest { requestName [0] OID }
	op := tlv(0x80, []byte(OIDStartTLS))
	req := buildMessage(1, opExtendedRequest, op)

	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, 1<<16)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("reading the response: %v", err)
	}
	env, err := readEnvelope(buf[:n])
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	if env.OpTag != 0x78 {
		t.Fatalf("OpTag = 0x%02x, want 0x78 (ExtendedResponse)", env.OpTag)
	}
	if code := resultCodeOf(t, env.OpContent); code != byte(ResultUnwillingToPerform) {
		t.Errorf("resultCode = %d, want 53 (unwillingToPerform)", code)
	}
}

func caPool(t *testing.T, certFile string) *x509.CertPool {
	t.Helper()
	pem, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatalf("reading %s: %v", certFile, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatalf("%s: no usable PEM certificate", certFile)
	}
	return pool
}

// ldapCmdStdin runs an OpenLDAP client, passing ldif on standard input.
func (s *e2eSetup) ldapCmdStdin(t *testing.T, ldif string, bin string, args ...string) (string, int) {
	t.Helper()
	return s.ldapCmdEnv(t, bytes.NewReader([]byte(ldif)), bin, args...)
}

// ldapCmdEnv runs an OpenLDAP client with an optional standard input.
func (s *e2eSetup) ldapCmdEnv(t *testing.T, stdin io.Reader, bin string, args ...string) (string, int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin, args...)
	if stdin != nil {
		cmd.Stdin = stdin
	}
	cmd.Env = append(os.Environ(),
		"LDAPTLS_CACERT="+s.caFile,
		"LDAPTLS_REQCERT=demand",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return string(out), ee.ExitCode()
		}
		return string(out), -1
	}
	return string(out), 0
}
