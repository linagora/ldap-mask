// ber.go — minimal BER framing and BindRequest parsing.
//
// Design (§4.3): we decode ONLY the outer envelope (the LDAPMessage TLV) and,
// for the bind case alone, the content of the BindRequest. Everything else is
// treated as opaque and relayed byte for byte, which guarantees fidelity (no
// risk of altering an exotic control).
//
// We do NOT use a high-level LDAP client (§7). However, to *encode* the
// requests/responses that we synthesise, we rely on
// github.com/go-asn1-ber/asn1-ber. Decoding, for its part, is written by hand:
// it must preserve the original bytes verbatim.
package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// maxMessageSize bounds the size of an accepted LDAPMessage, to prevent a
// hostile length from causing a massive allocation (OOM).
const maxMessageSize = 64 << 20 // 64 MiB

// Envelope and operation tags (RFC 4511).
const (
	tagSequence       = 0x30 // LDAPMessage (SEQUENCE, definite form)
	tagInteger        = 0x02
	tagOctetString    = 0x04
	tagEnumerated     = 0x0a
	opUnbindRequest   = 0x42
	opBindRequest     = 0x60 // [APPLICATION 0]
	opExtendedRequest = 0x77 // [APPLICATION 23]
	authSimple        = 0x80 // [0] OCTET STRING
	authSASL          = 0xA3 // [3] SEQUENCE
)

// OIDStartTLS is the OID of the StartTLS extended operation (RFC 4511 / RFC 4513).
const OIDStartTLS = "1.3.6.1.4.1.1466.20037"

// ErrNotSimpleBind signals a SASL BindRequest ([3] SEQUENCE). The proxy must
// then relay the original bytes verbatim, without substitution (§3).
var ErrNotSimpleBind = errors.New("non-simple bind (SASL): relayed as is")

// Envelope describes an LDAPMessage read in full.
type Envelope struct {
	Raw       []byte // complete LDAPMessage, exactly as read
	MessageID int
	OpTag     byte   // e.g. 0x60 BindRequest, 0x63 SearchRequest, 0x42 UnbindRequest, 0x77 ExtendedRequest
	OpContent []byte // content bytes of the protocolOp TLV (without tag or length)
}

// ReadMessage reads exactly one LDAPMessage from r.
//
// Constraints (RFC 4511 §5.1):
//   - the outer tag must be 0x30 (SEQUENCE);
//   - the indefinite form (0x80) is rejected;
//   - the length is bounded by maxMessageSize.
//
// Any read deadline is managed by the caller (via net.Conn), not here.
func ReadMessage(r *bufio.Reader) (*Envelope, error) {
	raw := make([]byte, 0, 256)

	tag, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	raw = append(raw, tag)
	if tag != tagSequence {
		return nil, fmt.Errorf("BER: outer tag expected 0x30, got 0x%02x", tag)
	}

	length, lenRaw, err := readLength(r)
	if err != nil {
		return nil, err
	}
	raw = append(raw, lenRaw...)

	content := make([]byte, length)
	if _, err := io.ReadFull(r, content); err != nil {
		return nil, err
	}
	raw = append(raw, content...)

	messageID, opTag, opContent, err := parseEnvelopeContent(content)
	if err != nil {
		return nil, err
	}

	return &Envelope{
		Raw:       raw,
		MessageID: messageID,
		OpTag:     opTag,
		OpContent: opContent,
	}, nil
}

// readLength reads the BER length in definite form and also returns the raw
// bytes consumed (needed to rebuild the envelope verbatim).
func readLength(r *bufio.Reader) (int, []byte, error) {
	b0, err := r.ReadByte()
	if err != nil {
		return 0, nil, err
	}
	raw := []byte{b0}

	if b0 == 0x80 {
		return 0, nil, errors.New("BER: indefinite length forbidden (RFC 4511 §5.1)")
	}
	if b0 < 0x80 {
		return int(b0), raw, nil
	}

	n := int(b0 & 0x7f)
	if n == 0 || n > 4 {
		return 0, nil, fmt.Errorf("BER: invalid long length (%d bytes)", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return 0, nil, err
	}
	raw = append(raw, buf...)

	length, err := decodeLength(buf)
	if err != nil {
		return 0, nil, err
	}
	return length, raw, nil
}

// decodeLength converts the n bytes of the long form into an integer, rejecting
// non-minimal encodings (easy to detect, so we do it).
func decodeLength(buf []byte) (int, error) {
	if buf[0] == 0 {
		return 0, errors.New("BER: non-minimal length (leading zero byte)")
	}
	length := 0
	for _, c := range buf {
		length = length<<8 | int(c)
	}
	if length < 0x80 {
		return 0, errors.New("BER: non-minimal length (pointless long form)")
	}
	if length > maxMessageSize {
		return 0, fmt.Errorf("BER: message too large (%d > %d)", length, maxMessageSize)
	}
	return length, nil
}

// cursor is a TLV reader bounded to a byte slice. Every read is checked against
// the size of the slice: a malformed packet returns an error, never a panic.
type cursor struct {
	b   []byte
	off int
}

// readTLV reads a complete TLV and returns the tag and the content bytes.
func (c *cursor) readTLV() (byte, []byte, error) {
	if c.off >= len(c.b) {
		return 0, nil, io.ErrUnexpectedEOF
	}
	tag := c.b[c.off]
	c.off++

	length, err := c.readLength()
	if err != nil {
		return 0, nil, err
	}
	if length > len(c.b)-c.off {
		return 0, nil, io.ErrUnexpectedEOF
	}
	val := c.b[c.off : c.off+length]
	c.off += length
	return tag, val, nil
}

// readLength reads a definite BER length from the current slice.
func (c *cursor) readLength() (int, error) {
	if c.off >= len(c.b) {
		return 0, io.ErrUnexpectedEOF
	}
	b0 := c.b[c.off]
	c.off++

	if b0 == 0x80 {
		return 0, errors.New("BER: indefinite length forbidden (RFC 4511 §5.1)")
	}
	if b0 < 0x80 {
		return int(b0), nil
	}

	n := int(b0 & 0x7f)
	if n == 0 || n > 4 {
		return 0, fmt.Errorf("BER: invalid long length (%d bytes)", n)
	}
	if n > len(c.b)-c.off {
		return 0, io.ErrUnexpectedEOF
	}
	buf := c.b[c.off : c.off+n]
	c.off += n
	return decodeLength(buf)
}

// parseEnvelopeContent decomposes the content of LDAPMessage:
// messageID INTEGER then protocolOp TLV. Any controls that follow are ignored
// (but preserved in Raw).
func parseEnvelopeContent(content []byte) (int, byte, []byte, error) {
	c := &cursor{b: content}

	tag, val, err := c.readTLV()
	if err != nil {
		return 0, 0, nil, fmt.Errorf("BER: reading messageID: %w", err)
	}
	if tag != tagInteger {
		return 0, 0, nil, fmt.Errorf("BER: messageID expected INTEGER (0x02), got 0x%02x", tag)
	}
	messageID, err := parseInt(val)
	if err != nil {
		return 0, 0, nil, fmt.Errorf("BER: invalid messageID: %w", err)
	}

	opTag, opContent, err := c.readTLV()
	if err != nil {
		return 0, 0, nil, fmt.Errorf("BER: reading protocolOp: %w", err)
	}
	return messageID, opTag, opContent, nil
}

// parseInt decodes a non-negative BER INTEGER (bounded).
func parseInt(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, errors.New("empty INTEGER")
	}
	if len(b) > 8 {
		return 0, fmt.Errorf("INTEGER too large (%d bytes)", len(b))
	}
	if b[0]&0x80 != 0 {
		return 0, errors.New("negative INTEGER not supported")
	}
	v := 0
	for _, c := range b {
		v = v<<8 | int(c)
	}
	return v, nil
}

// BindRequest represents a decoded LDAP BindRequest.
type BindRequest struct {
	Version  int
	DN       string
	AuthTag  byte   // 0x80 = simple, 0xA3 = sasl
	Password []byte // set only if AuthTag == 0x80
}

// ParseBindRequest parses the content bytes of a protocolOp 0x60.
//
// Returns ErrNotSimpleBind (sentinel) when AuthTag == 0xA3: the caller then
// relays the original bytes verbatim.
func ParseBindRequest(content []byte) (*BindRequest, error) {
	c := &cursor{b: content}

	tag, val, err := c.readTLV()
	if err != nil {
		return nil, fmt.Errorf("BindRequest: version: %w", err)
	}
	if tag != tagInteger {
		return nil, fmt.Errorf("BindRequest: version expected INTEGER (0x02), got 0x%02x", tag)
	}
	version, err := parseInt(val)
	if err != nil {
		return nil, fmt.Errorf("BindRequest: invalid version: %w", err)
	}

	tag, val, err = c.readTLV()
	if err != nil {
		return nil, fmt.Errorf("BindRequest: name: %w", err)
	}
	if tag != tagOctetString {
		return nil, fmt.Errorf("BindRequest: name expected OCTET STRING (0x04), got 0x%02x", tag)
	}
	name := string(val)

	tag, val, err = c.readTLV()
	if err != nil {
		return nil, fmt.Errorf("BindRequest: authentication: %w", err)
	}

	switch tag {
	case authSASL:
		return nil, ErrNotSimpleBind
	case authSimple:
		return &BindRequest{
			Version:  version,
			DN:       name,
			AuthTag:  authSimple,
			Password: val,
		}, nil
	default:
		return nil, fmt.Errorf("BindRequest: unknown authentication method 0x%02x", tag)
	}
}

// ParseExtendedRequestName returns the requestName (OID) of a protocolOp 0x77
// content. The value is carried by the primitive context tag 0x80.
// Returns "" if absent.
func ParseExtendedRequestName(content []byte) (string, error) {
	c := &cursor{b: content}
	tag, val, err := c.readTLV()
	if err != nil {
		return "", err
	}
	if tag != authSimple { // 0x80 = [0] requestName
		return "", nil
	}
	return string(val), nil
}

// encodeResultResponse builds an LDAPMessage carrying an application response
// (BindResponse [APPLICATION 1] or ExtendedResponse [APPLICATION 24]) with an
// empty matchedDN.
func encodeResultResponse(messageID int, appTag ber.Tag, code ResultCode, diagnostic, description string) ([]byte, error) {
	resp := ber.Encode(ber.ClassApplication, ber.TypeConstructed, appTag, nil, description)
	// resultCode is an ENUMERATED; our codes fit in one byte (< 128).
	resp.AppendChild(ber.Encode(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, []byte{byte(code)}, "resultCode"))
	resp.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN"))
	resp.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, diagnostic, "diagnosticMessage"))

	msg := ber.NewSequence("LDAPMessage")
	msg.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(messageID), "messageID"))
	msg.AppendChild(resp)
	return msg.Bytes(), nil
}

// EncodeBindRequest builds a complete LDAPMessage containing a simple
// version 3 BindRequest. This substituted message is what goes to the upstream
// (§4.1).
func EncodeBindRequest(messageID int, dn string, password []byte) ([]byte, error) {
	const version = 3
	// authentication CHOICE { simple [0] OCTET STRING }. The asn1-ber package
	// does not write a value for context tag 0, so we fill in Data ourselves.
	auth := ber.Encode(ber.ClassContext, ber.TypePrimitive, ber.Tag(0), nil, "simple")
	auth.Data.Write(password)

	bind := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ber.Tag(0), nil, "BindRequest")
	bind.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(version), "version"))
	bind.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, dn, "name"))
	bind.AppendChild(auth)

	msg := ber.NewSequence("LDAPMessage")
	msg.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(messageID), "messageID"))
	msg.AppendChild(bind)
	return msg.Bytes(), nil
}

// ResultCode is an LDAP result code (RFC 4511 §4.1.9).
type ResultCode uint8

// Result codes used by the proxy.
const (
	ResultSuccess            ResultCode = 0
	ResultProtocolError      ResultCode = 2 // RFC 4511 §4.2.1: malformed PDU or unsupported version
	ResultInvalidCredentials ResultCode = 49
	ResultUnwillingToPerform ResultCode = 53
)

// EncodeBindResponse builds a complete LDAPMessage: BindResponse
// ([APPLICATION 1]) with an empty matchedDN.
func EncodeBindResponse(messageID int, code ResultCode, diagnostic string) ([]byte, error) {
	return encodeResultResponse(messageID, ber.Tag(1), code, diagnostic, "BindResponse")
}

// EncodeExtendedResponse builds a complete LDAPMessage: ExtendedResponse
// ([APPLICATION 24]).
func EncodeExtendedResponse(messageID int, code ResultCode, diagnostic string) ([]byte, error) {
	return encodeResultResponse(messageID, ber.Tag(24), code, diagnostic, "ExtendedResponse")
}
