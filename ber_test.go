package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// tlv encodes a BER TLV (short or long length, minimal form). Used only by the
// tests to build entries by hand.
func tlv(tag byte, content []byte) []byte {
	out := []byte{tag}
	n := len(content)
	if n < 0x80 {
		out = append(out, byte(n))
	} else {
		var lb []byte
		for v := n; v > 0; v >>= 8 {
			lb = append([]byte{byte(v)}, lb...)
		}
		out = append(out, byte(0x80|len(lb)))
		out = append(out, lb...)
	}
	return append(out, content...)
}

// buildMessage assembles a complete LDAPMessage from the operation tag and its
// content. messageID is assumed to fit in one byte.
func buildMessage(msgID byte, opTag byte, opContent []byte) []byte {
	body := tlv(tagInteger, []byte{msgID})
	body = append(body, tlv(opTag, opContent)...)
	return tlv(tagSequence, body)
}

// readEnvelope reads an envelope from raw bytes.
func readEnvelope(b []byte) (*Envelope, error) {
	return ReadMessage(bufio.NewReader(bytes.NewReader(b)))
}

func TestBindRequestRoundTrip(t *testing.T) {
	dn := "cn=test-admin,dc=test"
	password := []byte("hunter2")

	raw, err := EncodeBindRequest(7, dn, password)
	if err != nil {
		t.Fatalf("EncodeBindRequest: %v", err)
	}

	env, err := readEnvelope(raw)
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	if env.MessageID != 7 {
		t.Errorf("messageID = %d, want 7", env.MessageID)
	}
	if env.OpTag != opBindRequest {
		t.Errorf("OpTag = 0x%02x, want 0x%02x", env.OpTag, opBindRequest)
	}
	if !bytes.Equal(env.Raw, raw) {
		t.Errorf("Raw not faithful:\n  got     %s\n  want %s", hex.EncodeToString(env.Raw), hex.EncodeToString(raw))
	}

	bind, err := ParseBindRequest(env.OpContent)
	if err != nil {
		t.Fatalf("ParseBindRequest: %v", err)
	}
	if bind.Version != 3 {
		t.Errorf("version = %d, want 3", bind.Version)
	}
	if bind.DN != dn {
		t.Errorf("DN = %q, want %q", bind.DN, dn)
	}
	if bind.AuthTag != authSimple {
		t.Errorf("AuthTag = 0x%02x, want 0x%02x", bind.AuthTag, authSimple)
	}
	if !bytes.Equal(bind.Password, password) {
		t.Errorf("password = %q, want %q", bind.Password, password)
	}
}

func TestLongFormLength(t *testing.T) {
	// A 200-byte DN guarantees content > 127: long-form encoding.
	dn := "cn=" + strings.Repeat("a", 200) + ",dc=test"
	raw, err := EncodeBindRequest(3, dn, []byte("secret"))
	if err != nil {
		t.Fatalf("EncodeBindRequest: %v", err)
	}

	// The first length byte must be in long form (0x81/0x82).
	if raw[1]&0x80 == 0 {
		t.Fatalf("long form expected, length byte = 0x%02x", raw[1])
	}

	env, err := readEnvelope(raw)
	if err != nil {
		t.Fatalf("ReadMessage (long form): %v", err)
	}
	bind, err := ParseBindRequest(env.OpContent)
	if err != nil {
		t.Fatalf("ParseBindRequest: %v", err)
	}
	if bind.DN != dn {
		t.Errorf("DN = %q, want %q", bind.DN, dn)
	}
}

func TestRejectIndefiniteLength(t *testing.T) {
	// SEQUENCE with indefinite length (0x80): forbidden by RFC 4511 §5.1.
	_, err := readEnvelope([]byte{tagSequence, 0x80, 0x00, 0x00})
	if err == nil {
		t.Fatal("indefinite length wrongly accepted")
	}
	if !strings.Contains(err.Error(), "indefinite") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestRejectTruncatedMessage(t *testing.T) {
	valid, err := EncodeBindRequest(1, "cn=x,dc=test", []byte("p"))
	if err != nil {
		t.Fatalf("EncodeBindRequest: %v", err)
	}

	cases := map[string][]byte{
		"header only":         {tagSequence, 0x10},
		"partial content":     valid[:len(valid)-1],
		"truncated long form": {tagSequence, 0x82, 0x01},
		"empty message":       {},
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := readEnvelope(raw); err == nil {
				t.Fatalf("truncated message wrongly accepted (%s)", hex.EncodeToString(raw))
			}
		})
	}
}

func TestRejectNonMinimalLength(t *testing.T) {
	// Long length with a leading zero byte: non-minimal.
	_, err := readEnvelope([]byte{tagSequence, 0x82, 0x00, 0x03, 0x02, 0x01, 0x01})
	if err == nil {
		t.Fatal("non-minimal length wrongly accepted")
	}
	// Pointless long length (value < 128).
	_, err = readEnvelope([]byte{tagSequence, 0x81, 0x03, 0x02, 0x01, 0x01})
	if err == nil {
		t.Fatal("pointless long length wrongly accepted")
	}
}

func TestParseBindRequestSASL(t *testing.T) {
	content := tlv(tagInteger, []byte{3})
	content = append(content, tlv(tagOctetString, []byte("cn=x,dc=test"))...)
	content = append(content, tlv(authSASL, []byte{0x04, 0x00})...)

	if _, err := ParseBindRequest(content); !errors.Is(err, ErrNotSimpleBind) {
		t.Fatalf("err = %v, want ErrNotSimpleBind", err)
	}
}

func TestParseExtendedRequestName(t *testing.T) {
	content := tlv(authSimple, []byte(OIDStartTLS))
	name, err := ParseExtendedRequestName(content)
	if err != nil {
		t.Fatalf("ParseExtendedRequestName: %v", err)
	}
	if name != OIDStartTLS {
		t.Errorf("OID = %q, want %q", name, OIDStartTLS)
	}

	// requestName absent: first TLV is not 0x80.
	name, err = ParseExtendedRequestName(tlv(tagInteger, []byte{1}))
	if err != nil {
		t.Fatalf("ParseExtendedRequestName (absent): %v", err)
	}
	if name != "" {
		t.Errorf("OID = %q, want empty", name)
	}
}

func TestEncodeResultResponses(t *testing.T) {
	raw, err := EncodeBindResponse(42, ResultInvalidCredentials, "")
	if err != nil {
		t.Fatalf("EncodeBindResponse: %v", err)
	}
	env, err := readEnvelope(raw)
	if err != nil {
		t.Fatalf("ReadMessage(BindResponse): %v", err)
	}
	if env.MessageID != 42 {
		t.Errorf("messageID = %d, want 42", env.MessageID)
	}
	if env.OpTag != 0x61 {
		t.Errorf("OpTag = 0x%02x, want 0x61 (BindResponse)", env.OpTag)
	}
	if code := resultCodeOf(t, env.OpContent); code != byte(ResultInvalidCredentials) {
		t.Errorf("resultCode = %d, want %d", code, ResultInvalidCredentials)
	}

	raw, err = EncodeExtendedResponse(5, ResultUnwillingToPerform, "not supported")
	if err != nil {
		t.Fatalf("EncodeExtendedResponse: %v", err)
	}
	env, err = readEnvelope(raw)
	if err != nil {
		t.Fatalf("ReadMessage(ExtendedResponse): %v", err)
	}
	if env.OpTag != 0x78 {
		t.Errorf("OpTag = 0x%02x, want 0x78 (ExtendedResponse)", env.OpTag)
	}
	if code := resultCodeOf(t, env.OpContent); code != byte(ResultUnwillingToPerform) {
		t.Errorf("resultCode = %d, want %d", code, ResultUnwillingToPerform)
	}
}

// resultCodeOf extracts the resultCode from a response content.
func resultCodeOf(t *testing.T, opContent []byte) byte {
	t.Helper()
	c := &cursor{b: opContent}
	tag, val, err := c.readTLV()
	if err != nil {
		t.Fatalf("reading resultCode: %v", err)
	}
	if tag != tagEnumerated {
		t.Fatalf("tag = 0x%02x, want ENUMERATED (0x0a)", tag)
	}
	if len(val) == 0 {
		t.Fatal("empty resultCode")
	}
	return val[0]
}

// TestMalformedNoPanic feeds a series of malformed inputs to the decoder and
// checks that none of them panics.
func TestMalformedNoPanic(t *testing.T) {
	inputs := [][]byte{
		nil,
		{},
		{0x30},
		{0x30, 0x80},
		{0x30, 0xff, 0xff, 0xff, 0xff, 0xff},
		{0x30, 0x84, 0xff, 0xff, 0xff, 0xff},
		{0x31, 0x00},
		{0x30, 0x03, 0x02, 0x01, 0x01},       // no protocolOp
		{0x30, 0x05, 0x02, 0x00, 0x60, 0x00}, // empty messageID + empty op
		{0x30, 0x04, 0x04, 0x02, 0x41, 0x42}, // first field not INTEGER
		{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x02, 0x00, 0x00}, // op = INTEGER
		{0x30, 0x06, 0x02, 0x01, 0x80, 0x60, 0x01, 0x02},       // negative messageID
	}
	for i, in := range inputs {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("input %d caused a panic: %v (%s)", i, r, hex.EncodeToString(in))
				}
			}()
			env, err := readEnvelope(in)
			if err == nil && env != nil {
				_, _ = ParseBindRequest(env.OpContent)
			}
		}()
	}

	// Malformed BindRequest contents (no panic).
	binds := [][]byte{
		nil,
		{},
		{tagInteger, 0x01, 0x03}, // no name
		{tagInteger, 0x01, 0x03, tagOctetString, 0x02, 0x41, 0x42}, // no auth
		{tagOctetString, 0x00}, // first field not INTEGER
		{tagInteger, 0x00, tagOctetString, 0x00, authSimple, 0x00},                               // empty version
		{tagInteger, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, tagOctetString, 0x00, authSimple, 0x00}, // INTEGER 5 bytes
	}
	for i, in := range binds {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("bind %d caused a panic: %v", i, r)
				}
			}()
			_, _ = ParseBindRequest(in)
			_, _ = ParseExtendedRequestName(in)
		}()
	}
}
