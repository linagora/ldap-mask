package main

// tls_test.go — tests for the upstream TLS configuration.
//
// This is the §6.4 production path: `ca_file`, `RootCAs` and `ServerName` are
// what actually authenticate the upstream. The e2e tests cannot cover it — they
// run against a container whose certificate is regenerated at every start, so
// they have to disable verification. These unit tests are the only place the
// verification path is exercised at all.

import (
	"crypto/tls"
	"crypto/x509"
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

// upstreamTLSFor runs buildUpstreamTLS on a configuration whose upstream is raw.
func upstreamTLSFor(t *testing.T, upstreamURL, caFile string, insecure bool) (*tls.Config, error) {
	t.Helper()
	u, err := url.Parse(upstreamURL)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", upstreamURL, err)
	}
	cfg := &Config{Upstream: UpstreamConfig{
		URL:                upstreamURL,
		CAFile:             caFile,
		InsecureSkipVerify: insecure,
	}}
	return buildUpstreamTLS(cfg, u)
}

// TestBuildUpstreamTLSCleartext: an ldap:// upstream needs no TLS at all.
func TestBuildUpstreamTLSCleartext(t *testing.T) {
	tlsCfg, err := upstreamTLSFor(t, "ldap://directory.internal:389", "/nonexistent/ca.crt", false)
	if err != nil {
		t.Fatalf("buildUpstreamTLS: %v", err)
	}
	if tlsCfg != nil {
		t.Errorf("tls.Config = %+v, want nil for a cleartext upstream", tlsCfg)
	}
}

// TestBuildUpstreamTLSNoCA: without ca_file, the system roots are used (RootCAs
// stays nil) but the hostname to verify is still pinned.
func TestBuildUpstreamTLSNoCA(t *testing.T) {
	tlsCfg, err := upstreamTLSFor(t, "ldaps://directory.internal:636", "", false)
	if err != nil {
		t.Fatalf("buildUpstreamTLS: %v", err)
	}
	if tlsCfg == nil {
		t.Fatal("tls.Config = nil for an ldaps:// upstream")
	}
	if tlsCfg.ServerName != "directory.internal" {
		t.Errorf("ServerName = %q, want %q", tlsCfg.ServerName, "directory.internal")
	}
	if tlsCfg.RootCAs != nil {
		t.Error("RootCAs set although no ca_file was given: the system roots must be used")
	}
	if tlsCfg.InsecureSkipVerify {
		t.Error("InsecureSkipVerify set although the configuration did not ask for it")
	}
}

// TestBuildUpstreamTLSCAFileLoads: a valid ca_file populates RootCAs with
// exactly the certificates of that file — compared, not counted, so a pool
// holding a single wrong certificate cannot pass.
func TestBuildUpstreamTLSCAFileLoads(t *testing.T) {
	dir := t.TempDir()
	caFile := selfSignedCert(t, dir)

	tlsCfg, err := upstreamTLSFor(t, "ldaps://127.0.0.1:636", caFile, false)
	if err != nil {
		t.Fatalf("buildUpstreamTLS: %v", err)
	}
	if tlsCfg == nil || tlsCfg.RootCAs == nil {
		t.Fatal("RootCAs not populated from ca_file")
	}

	// Compare the pool against one built from the same file. Counting
	// certificates would not do: a pool holding a single but WRONG certificate
	// counts 1 as well.
	pem, err := os.ReadFile(caFile)
	if err != nil {
		t.Fatalf("reading %s: %v", caFile, err)
	}
	want := x509.NewCertPool()
	if !want.AppendCertsFromPEM(pem) {
		t.Fatal("the generated ca_file is not usable PEM")
	}
	if !tlsCfg.RootCAs.Equal(want) {
		t.Error("RootCAs does not hold exactly the certificates of ca_file")
	}
}

// TestBuildUpstreamTLSCAFileErrors: a missing or non-PEM ca_file must fail at
// startup, not at the first connection.
func TestBuildUpstreamTLSCAFileErrors(t *testing.T) {
	t.Run("missing file", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "absent.crt")
		if _, err := upstreamTLSFor(t, "ldaps://127.0.0.1:636", missing, false); err == nil {
			t.Fatal("buildUpstreamTLS accepted a ca_file that does not exist")
		}
	})

	t.Run("not a certificate", func(t *testing.T) {
		notPEM := filepath.Join(t.TempDir(), "garbage.crt")
		if err := os.WriteFile(notPEM, []byte("this is not a certificate\n"), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		if _, err := upstreamTLSFor(t, "ldaps://127.0.0.1:636", notPEM, false); err == nil {
			t.Fatal("buildUpstreamTLS accepted a ca_file holding no usable PEM certificate")
		}
	})
}

// TestBuildUpstreamTLSInsecurePropagates: the flag reaches the tls.Config.
// Validate() is what refuses it by default; buildUpstreamTLS must still honor
// it once the override has been granted.
func TestBuildUpstreamTLSInsecurePropagates(t *testing.T) {
	tlsCfg, err := upstreamTLSFor(t, "ldaps://127.0.0.1:636", "", true)
	if err != nil {
		t.Fatalf("buildUpstreamTLS: %v", err)
	}
	if tlsCfg == nil || !tlsCfg.InsecureSkipVerify {
		t.Error("insecure_skip_verify not propagated to the tls.Config")
	}
	if tlsCfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = 0x%04x, want TLS 1.2", tlsCfg.MinVersion)
	}
}
