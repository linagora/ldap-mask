package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"
)

// testRig wires a fake client connection onto handleConn, with an "upstream" in
// net.Pipe whose two ends we control.
type testRig struct {
	client   net.Conn // test side end: we write the requests / read the responses there
	upstream net.Conn // test side end: we read the requests / write the responses there
}

func newRig(t *testing.T, cfg *Config) *testRig {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	p, err := New(cfg, logger)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	clientProxy, clientTest := net.Pipe()
	upstreamProxy, upstreamTest := net.Pipe()
	p.dialUpstream = func(ctx context.Context) (net.Conn, error) {
		return upstreamProxy, nil
	}

	go p.handleConn(context.Background(), clientProxy)

	t.Cleanup(func() {
		_ = clientTest.Close()
		_ = upstreamTest.Close()
	})
	return &testRig{client: clientTest, upstream: upstreamTest}
}

func testConfig(t *testing.T, allowUnmapped bool) *Config {
	t.Helper()
	hash, err := HashPassword("hunter2")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	return &Config{
		Listen: "ldaps://127.0.0.1:0",
		Upstream: UpstreamConfig{
			URL: "ldap://127.0.0.1:389",
		},
		Mappings: []Mapping{{
			LocalDN:             "cn=test-admin,dc=test",
			LocalPasswordBcrypt: hash,
			RemoteDN:            "cn=admin,dc=example,dc=com",
			RemotePassword:      "s3cret-upstream",
		}},
		AllowUnmappedBind: allowUnmapped,
	}
}

// bindContent builds the content of a simple BindRequest protocolOp.
func bindContent(dn, password string) []byte {
	c := tlv(tagInteger, []byte{3})
	c = append(c, tlv(tagOctetString, []byte(dn))...)
	c = append(c, tlv(authSimple, []byte(password))...)
	return c
}

// readOne reads a response from c, with a deadline.
func readOne(t *testing.T, c net.Conn) []byte {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	// The deadline is cleared on return; an error here would only mean the
	// connection is already gone, which the caller handles.
	defer func() { _ = c.SetReadDeadline(time.Time{}) }()
	buf := make([]byte, 1<<16)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	return append([]byte(nil), buf[:n]...)
}

// exchange sends req and returns the proxy's response.
func exchange(t *testing.T, c net.Conn, req []byte) []byte {
	t.Helper()
	go func() { _, _ = c.Write(req) }()
	return readOne(t, c)
}

// readUpstream reads a message emitted by the proxy toward the upstream, with a
// deadline.
func readUpstream(t *testing.T, c net.Conn) []byte {
	t.Helper()
	ch := make(chan []byte, 1)
	go func() {
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, 1<<16)
		n, err := c.Read(buf)
		if err != nil {
			ch <- nil
			return
		}
		ch <- append([]byte(nil), buf[:n]...)
	}()
	select {
	case b := <-ch:
		if b == nil {
			t.Fatal("no data received on the upstream")
		}
		return b
	case <-time.After(4 * time.Second):
		t.Fatal("timeout waiting for upstream data")
		return nil
	}
}

// TestLocalRefusalResponsesIdentical checks that "unmapped DN" and "wrong
// password" produce STRICTLY identical BindResponses (design §4.1): otherwise
// a client could enumerate the mapped accounts.
func TestLocalRefusalResponsesIdentical(t *testing.T) {
	rig := newRig(t, testConfig(t, false))

	unmapped := buildMessage(1, opBindRequest, bindContent("cn=unknown,dc=test", "whatever"))
	wrongPassword := buildMessage(1, opBindRequest, bindContent("cn=test-admin,dc=test", "wrong"))

	respUnmapped := exchange(t, rig.client, unmapped)
	respWrongPw := exchange(t, rig.client, wrongPassword)

	if !bytes.Equal(respUnmapped, respWrongPw) {
		t.Fatalf("the two refusals differ (enumeration possible):\n  unmapped  %x\n  wrong pw  %x",
			respUnmapped, respWrongPw)
	}

	env, err := readEnvelope(respUnmapped)
	if err != nil {
		t.Fatalf("ReadMessage(refusal): %v", err)
	}
	if env.OpTag != 0x61 {
		t.Errorf("OpTag = 0x%02x, want 0x61 (BindResponse)", env.OpTag)
	}
	if code := resultCodeOf(t, env.OpContent); code != byte(ResultInvalidCredentials) {
		t.Errorf("resultCode = %d, want 49", code)
	}
}

// TestSubstitutedBindAndVerbatimResponse checks that a successful local bind is
// replaced by the upstream pair (same messageID), and that the upstream
// BindResponse is relayed verbatim.
func TestSubstitutedBindAndVerbatimResponse(t *testing.T) {
	rig := newRig(t, testConfig(t, false))

	req := buildMessage(9, opBindRequest, bindContent("cn=test-admin,dc=test", "hunter2"))
	go func() { _, _ = rig.client.Write(req) }()

	upReq := readUpstream(t, rig.upstream)

	env, err := readEnvelope(upReq)
	if err != nil {
		t.Fatalf("ReadMessage(upstream): %v", err)
	}
	if env.MessageID != 9 {
		t.Errorf("upstream messageID = %d, want 9 (must be kept)", env.MessageID)
	}
	bind, err := ParseBindRequest(env.OpContent)
	if err != nil {
		t.Fatalf("ParseBindRequest(upstream): %v", err)
	}
	if bind.DN != "cn=admin,dc=example,dc=com" {
		t.Errorf("upstream DN = %q", bind.DN)
	}
	if string(bind.Password) != "s3cret-upstream" {
		t.Errorf("upstream password = %q", bind.Password)
	}
	if bytes.Contains(upReq, []byte("cn=test-admin")) {
		t.Error("the local DN leaks to the upstream")
	}

	// The upstream response must be relayed as is.
	upstreamResp, err := EncodeBindResponse(9, ResultSuccess, "")
	if err != nil {
		t.Fatalf("EncodeBindResponse: %v", err)
	}
	go func() { _, _ = rig.upstream.Write(upstreamResp) }()

	got := readOne(t, rig.client)
	if !bytes.Equal(got, upstreamResp) {
		t.Fatalf("upstream response not relayed verbatim:\n  got  %x\n  want %x", got, upstreamResp)
	}
}

// TestAllowUnmappedBindForwarded: with allow_unmapped_bind, the unmapped bind
// is relayed verbatim.
func TestAllowUnmappedBindForwarded(t *testing.T) {
	rig := newRig(t, testConfig(t, true))
	req := buildMessage(2, opBindRequest, bindContent("cn=unknown,dc=test", "x"))
	go func() { _, _ = rig.client.Write(req) }()

	got := readUpstream(t, rig.upstream)
	if !bytes.Equal(got, req) {
		t.Fatalf("unmapped bind not relayed verbatim:\n  got  %x\n  want %x", got, req)
	}
}

// TestSASLBindForwardedVerbatim: a SASL bind is relayed byte for byte.
func TestSASLBindForwardedVerbatim(t *testing.T) {
	rig := newRig(t, testConfig(t, false))

	content := tlv(tagInteger, []byte{3})
	content = append(content, tlv(tagOctetString, []byte("cn=x,dc=test"))...)
	content = append(content, tlv(authSASL, []byte{0x04, 0x00})...) // empty SEQUENCE
	req := buildMessage(3, opBindRequest, content)

	go func() { _, _ = rig.client.Write(req) }()
	got := readUpstream(t, rig.upstream)
	if !bytes.Equal(got, req) {
		t.Fatalf("SASL bind not relayed verbatim:\n  got  %x\n  want %x", got, req)
	}
}

// TestStartTLSRefused: StartTLS is refused locally (unwillingToPerform) and is
// NOT forwarded to the upstream.
func TestStartTLSRefused(t *testing.T) {
	rig := newRig(t, testConfig(t, false))

	opContent := tlv(authSimple, []byte(OIDStartTLS))
	req := buildMessage(4, opExtendedRequest, opContent)

	resp := exchange(t, rig.client, req)
	env, err := readEnvelope(resp)
	if err != nil {
		t.Fatalf("ReadMessage(StartTLS): %v", err)
	}
	if env.OpTag != 0x78 {
		t.Errorf("OpTag = 0x%02x, want 0x78 (ExtendedResponse)", env.OpTag)
	}
	if code := resultCodeOf(t, env.OpContent); code != byte(ResultUnwillingToPerform) {
		t.Errorf("resultCode = %d, want 53", code)
	}

	// The upstream must have received nothing.
	_ = rig.upstream.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
	buf := make([]byte, 64)
	if n, err := rig.upstream.Read(buf); err == nil {
		t.Fatalf("StartTLS wrongly forwarded to the upstream (%d bytes: %x)", n, buf[:n])
	}
}

// TestOtherExtendedForwarded: an extended operation other than StartTLS is
// relayed verbatim (e.g. WhoAmI).
func TestOtherExtendedForwarded(t *testing.T) {
	rig := newRig(t, testConfig(t, false))

	opContent := tlv(authSimple, []byte("1.3.6.1.4.1.4203.1.11.3")) // WhoAmI
	req := buildMessage(5, opExtendedRequest, opContent)

	go func() { _, _ = rig.client.Write(req) }()
	got := readUpstream(t, rig.upstream)
	if !bytes.Equal(got, req) {
		t.Fatalf("extended operation not relayed verbatim:\n  got  %x\n  want %x", got, req)
	}
}

// TestFailedRebindAfterUpstreamBindClosesConnection is a non-regression test on
// an authorization flaw.
//
// After a successful substituted bind, the upstream connection carries the real
// identity. If the client then sends a bind that fails LOCALLY, the proxy
// answers 49 — it therefore believes itself anonymous — whereas the upstream is
// still bound: the client would keep working with the rights of the previous
// identity. §4.1 requires that "a failed bind resets the state" (RFC 4511
// §4.2.1). Unable to re-anonymize the upstream without parsing the relayed
// stream (which §4.2 forbids), the proxy must close the connection.
func TestFailedRebindAfterUpstreamBindClosesConnection(t *testing.T) {
	rig := newRig(t, testConfig(t, false))

	// 1. First bind: substituted, the upstream receives the real pair.
	first := buildMessage(1, opBindRequest, bindContent("cn=test-admin,dc=test", "hunter2"))
	go func() { _, _ = rig.client.Write(first) }()

	upReq := readUpstream(t, rig.upstream)
	firstEnv, err := readEnvelope(upReq)
	if err != nil {
		t.Fatalf("ReadMessage(upstream): %v", err)
	}

	// The upstream answers OK; the response is relayed verbatim to the client.
	upResp, err := EncodeBindResponse(firstEnv.MessageID, ResultSuccess, "")
	if err != nil {
		t.Fatalf("EncodeBindResponse: %v", err)
	}
	go func() { _, _ = rig.upstream.Write(upResp) }()
	if got := readOne(t, rig.client); !bytes.Equal(got, upResp) {
		t.Fatalf("response of the first bind not relayed:\n  got  %x\n  want %x", got, upResp)
	}

	// 2. Second bind on the SAME connection, invalid local password.
	second := buildMessage(2, opBindRequest, bindContent("cn=test-admin,dc=test", "wrong"))
	go func() { _, _ = rig.client.Write(second) }()

	refusal := readOne(t, rig.client)
	env, err := readEnvelope(refusal)
	if err != nil {
		t.Fatalf("ReadMessage(refusal): %v", err)
	}
	if env.OpTag != 0x61 {
		t.Errorf("OpTag = 0x%02x, want 0x61 (BindResponse)", env.OpTag)
	}
	if code := resultCodeOf(t, env.OpContent); code != byte(ResultInvalidCredentials) {
		t.Errorf("resultCode = %d, want 49", code)
	}

	// 3. The connection must be closed: the upstream identity cannot be kept
	//    when we have just told the client it is anonymous.
	//
	//    Be careful not to confuse "closed" (EOF) and "open but idle" (read
	//    deadline reached): that is precisely the case this test must
	//    distinguish.
	_ = rig.client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	n, readErr := rig.client.Read(buf)
	if readErr == nil {
		t.Fatalf("the connection stays open after a refused rebind (%d bytes: %x)", n, buf[:n])
	}
	var netErr net.Error
	if errors.As(readErr, &netErr) && netErr.Timeout() {
		t.Fatal("the connection stays OPEN after a refused rebind: the client believes itself " +
			"anonymous whereas the upstream still carries the previous identity")
	}

	// 4. The refused bind must never have reached the upstream.
	_ = rig.upstream.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
	if n, err := rig.upstream.Read(buf); err == nil {
		t.Fatalf("the refused bind was forwarded to the upstream (%d bytes: %x)", n, buf[:n])
	}
}

// TestFailedRebindOnFreshConnectionStaysOpen: without a prior upstream
// identity, a local refusal must NOT close the connection (normal behavior,
// §4.1: the connection remains usable anonymously).
func TestFailedRebindOnFreshConnectionStaysOpen(t *testing.T) {
	rig := newRig(t, testConfig(t, false))

	req := buildMessage(7, opBindRequest, bindContent("cn=test-admin,dc=test", "wrong"))
	resp := exchange(t, rig.client, req)

	env, err := readEnvelope(resp)
	if err != nil {
		t.Fatalf("ReadMessage(refusal): %v", err)
	}
	if code := resultCodeOf(t, env.OpContent); code != byte(ResultInvalidCredentials) {
		t.Errorf("resultCode = %d, want 49", code)
	}

	// The connection must stay open: an anonymous search must go through.
	search := buildMessage(8, 0x63, []byte{tagOctetString, 0x03, 0x64, 0x63, 0x3d})
	go func() { _, _ = rig.client.Write(search) }()
	if got := readUpstream(t, rig.upstream); !bytes.Equal(got, search) {
		t.Fatalf("search not relayed after a local refusal:\n  got  %x\n  want %x", got, search)
	}
}

// TestRelayedMessageNotInterleavedWithSynthesizedResponse is a non-regression
// test on the integrity of the client stream.
//
// The upstream → client relay and the synthesized responses (§4.1) write to the
// same socket. If the relay released the lock BETWEEN TWO FRAGMENTS of the same
// message — which io.Copy does with its 32 KiB buffer —, a synthesized response
// could insert itself in the middle of a message being relayed: the client
// would read that response as the continuation of the previous message, and its
// BER decoder would desynchronize permanently.
//
// The test does not presume the order of the two writes: it accumulates
// everything the client receives, then checks that the stream decodes into a
// sequence of complete LDAP messages, with no residual byte.
func TestRelayedMessageNotInterleavedWithSynthesizedResponse(t *testing.T) {
	rig := newRig(t, testConfig(t, false))

	// 1. A search is relayed to the upstream.
	search := buildMessage(1, 0x63, []byte{tagOctetString, 0x03, 0x64, 0x63, 0x3d})
	go func() { _, _ = rig.client.Write(search) }()
	if got := readUpstream(t, rig.upstream); !bytes.Equal(got, search) {
		t.Fatal("the search was not relayed to the upstream")
	}

	// 2. The upstream returns a message much larger than io.Copy's 32 KiB
	//    buffer.
	big := buildMessage(1, 0x64, bytes.Repeat([]byte{0x04, 0x40}, 262144)) // 512 KiB
	if len(big) <= 32*1024 {
		t.Fatalf("test message too small (%d bytes)", len(big))
	}
	go func() { _, _ = rig.upstream.Write(big) }()

	// 3. We consume enough to put the relay mid-message, THEN send a request
	//    refused locally — so at the precise moment when a synthesized write
	//    can insert itself into the relay.
	//
	//    We use StartTLS rather than a refused bind: it is the proxy's fastest
	//    refusal (no bcrypt), hence the one most likely to arrive while the
	//    relay is still in progress.
	var all []byte
	readChunk := func(n int) int {
		buf := make([]byte, n)
		_ = rig.client.SetReadDeadline(time.Now().Add(5 * time.Second))
		got, err := rig.client.Read(buf)
		if err != nil {
			t.Fatalf("client read: %v", err)
		}
		all = append(all, buf[:got]...)
		return got
	}
	readChunk(4096)

	startTLS := buildMessage(9, opExtendedRequest, tlv(authSimple, []byte(OIDStartTLS)))
	go func() { _, _ = rig.client.Write(startTLS) }()

	// 4. We accumulate the rest, READING SLOWLY.
	//
	//    The slowness is deliberate: it spreads the relay over many writes and
	//    gives the synthesized response all the time it needs to insert itself
	//    if the lock is released between two fragments. This delay cannot make
	//    the correct implementation fail — that one holds the lock for the
	//    whole message, so the order stays right whatever the client's slowness;
	//    it only increases the chances of detecting the flaw.
	buf := make([]byte, 4096)
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) && len(all) < len(big)+16 {
		_ = rig.client.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := rig.client.Read(buf)
		all = append(all, buf[:n]...)
		if err != nil {
			break
		}
		time.Sleep(time.Millisecond)
	}

	if len(all) == 0 {
		t.Fatal("the client received nothing")
	}

	// 4. The stream must split into whole LDAP messages.
	var sawBig, sawRefusal bool
	remaining := all
	for len(remaining) > 0 {
		env, err := ReadMessage(bufio.NewReader(bytes.NewReader(remaining)))
		if err != nil {
			t.Fatalf("the client stream does not decode — interleaved write? (%v)\n"+
				"received (%d bytes):\n% x", err, len(all), all[:min(len(all), 160)])
		}
		switch {
		case bytes.Equal(env.Raw, big):
			sawBig = true
		case env.OpTag == 0x78:
			sawRefusal = true
		}
		remaining = remaining[len(env.Raw):]
	}

	if !sawBig {
		t.Error("the upstream message was not relayed intact")
	}
	if !sawRefusal {
		t.Error("the StartTLS refusal did not reach the client")
	}
}

// TestSearchForwardedVerbatim: any other operation (here a search) is relayed
// byte for byte.
func TestSearchForwardedVerbatim(t *testing.T) {
	rig := newRig(t, testConfig(t, false))

	req := buildMessage(6, 0x63, []byte{tagOctetString, 0x03, 0x64, 0x63, 0x3d})
	go func() { _, _ = rig.client.Write(req) }()
	got := readUpstream(t, rig.upstream)
	if !bytes.Equal(got, req) {
		t.Fatalf("search not relayed verbatim:\n  got  %x\n  want %x", got, req)
	}
}
