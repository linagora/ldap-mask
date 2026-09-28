// proxy.go — per-connection loop: verbatim relay, bind substitution.
//
// Architecture (DESIGN.md §4): one upstream connection per client connection
// (the "bound" state is a connection state, not shareable through a pool),
// opened lazily. Two goroutines exchange messages; a mutex serializes writes to
// the client, because the synthesized responses (§4.1) and the relayed stream
// (§4.2) write to the same socket.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	// dialTimeout bounds the establishment of the upstream connection (TCP +
	// TLS handshake), so as never to leave a client hanging.
	dialTimeout = 10 * time.Second

	// firstMessageTimeout bounds the wait for the FIRST client message. There
	// is deliberately no inactivity timeout afterwards: a long search
	// legitimately leaves the client silent while the results arrive. This
	// timeout is enough to prevent a socket opened then left mute from tying
	// up a goroutine indefinitely.
	firstMessageTimeout = 30 * time.Second
)

// Proxy is the delegated LDAP server.
type Proxy struct {
	cfg         *Config
	log         *slog.Logger
	upstreamURL *url.URL
	// upstreamDesc is the upstream URL with its userinfo stripped, for the logs.
	upstreamDesc string
	upstreamTLS  *tls.Config

	// dummyHash is a throwaway bcrypt hash, compared when a DN is not mapped.
	// Without it, "unmapped DN" would answer in a few microseconds whereas
	// "invalid password" takes a full bcrypt: the timing gap would make it
	// possible to enumerate the mapped DNs, which is precisely what §4.1 seeks
	// to prevent.
	dummyHash []byte

	// dialUpstream opens the connection to the upstream. Function field to
	// allow injecting a fake connection in the tests.
	dialUpstream func(ctx context.Context) (net.Conn, error)
}

// New builds a proxy from the validated configuration.
func New(cfg *Config, logger *slog.Logger) (*Proxy, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if cfg == nil {
		return nil, errors.New("nil configuration")
	}

	u, err := url.Parse(cfg.Upstream.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid upstream.url: %w", err)
	}
	if u.Scheme != "ldap" && u.Scheme != "ldaps" {
		return nil, fmt.Errorf("upstream.url %q: expected ldap:// or ldaps:// scheme", cfg.Upstream.URL)
	}

	dummy, err := bcrypt.GenerateFromPassword([]byte("ldap-mask-dummy"), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("dummy hash generation: %w", err)
	}

	p := &Proxy{
		cfg:          cfg,
		log:          logger,
		upstreamURL:  u,
		upstreamDesc: redactURL(u),
		dummyHash:    dummy,
	}

	tlsCfg, err := buildUpstreamTLS(cfg, u)
	if err != nil {
		return nil, err
	}
	p.upstreamTLS = tlsCfg
	p.dialUpstream = p.realDialUpstream
	return p, nil
}

// redactURL masks any userinfo in a URL before logging: a
// "ldaps://cn=admin:password@directory" must not land in the logs.
func redactURL(u *url.URL) string {
	if u.User == nil {
		return u.String()
	}
	c := *u
	c.User = url.User("***")
	return c.String()
}

// buildUpstreamTLS prepares the TLS configuration of the proxy → upstream leg.
// RootCAs comes from ca_file, and ServerName from the URL's host. Returns nil
// for a cleartext upstream (ldap://).
func buildUpstreamTLS(cfg *Config, u *url.URL) (*tls.Config, error) {
	if u.Scheme == "ldap" {
		return nil, nil
	}
	tlsCfg := &tls.Config{
		ServerName:         u.Hostname(),
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: cfg.Upstream.InsecureSkipVerify,
	}
	if cfg.Upstream.CAFile != "" {
		pem, err := os.ReadFile(cfg.Upstream.CAFile)
		if err != nil {
			return nil, fmt.Errorf("reading upstream CA %q: %w", cfg.Upstream.CAFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("upstream CA %q: no usable PEM certificate", cfg.Upstream.CAFile)
		}
		tlsCfg.RootCAs = pool
	}
	return tlsCfg, nil
}

// realDialUpstream opens the connection to the destination directory.
func (p *Proxy) realDialUpstream(ctx context.Context) (net.Conn, error) {
	addr := p.upstreamURL.Host
	if p.upstreamURL.Port() == "" {
		port := "389"
		if p.upstreamURL.Scheme == "ldaps" {
			port = "636"
		}
		addr = net.JoinHostPort(p.upstreamURL.Hostname(), port)
	}

	d := &net.Dialer{Timeout: dialTimeout}
	if p.upstreamURL.Scheme == "ldap" {
		return d.DialContext(ctx, "tcp", addr)
	}

	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	tconn := tls.Client(raw, p.upstreamTLS)

	hsCtx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	if err := tconn.HandshakeContext(hsCtx); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("upstream TLS handshake: %w", err)
	}
	return tconn, nil
}

// Serve accepts connections until the context is canceled, then waits for the
// in-flight connections to finish.
//
// A transient Accept error (EMFILE, ECONNABORTED…) must not kill the service:
// we retry with a bounded exponential backoff.
func (p *Proxy) Serve(ctx context.Context, l net.Listener) error {
	var wg sync.WaitGroup

	// Closing the listener unblocks Accept when the context is canceled.
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = l.Close()
		case <-done:
		}
	}()
	defer close(done)

	var retryDelay time.Duration
	for {
		conn, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				wg.Wait()
				return nil
			}

			if retryDelay == 0 {
				retryDelay = 5 * time.Millisecond
			} else {
				retryDelay *= 2
			}
			if retryDelay > time.Second {
				retryDelay = time.Second
			}
			p.log.Warn("accept failed, retrying", "error", err, "delay", retryDelay)

			select {
			case <-time.After(retryDelay):
			case <-ctx.Done():
			}
			continue
		}
		retryDelay = 0

		wg.Add(1)
		go func() {
			defer wg.Done()
			p.handleConn(ctx, conn)
		}()
	}
}

// connHandler carries the state of a client/upstream connection.
type connHandler struct {
	p      *Proxy
	ctx    context.Context
	client net.Conn

	// mu protects ALL writes to the client. It is taken for a WHOLE LDAP
	// message, never for a fragment: two producers write to this socket (the
	// upstream → client relay and the synthesized responses), and interleaving
	// in the middle of a message would desynchronize the client's BER decoder.
	mu sync.Mutex

	// Upstream connection, opened lazily on the first message to relay. upMu
	// protects the field, dialOnce guarantees a single attempt, and ready is
	// closed when that attempt has completed (or failed).
	upMu     sync.Mutex
	upstream net.Conn
	dialOnce sync.Once
	dialErr  error
	ready    chan struct{}

	// done is closed by closeFn: it unblocks the waiting goroutines.
	done chan struct{}

	// upstreamBound indicates that a bind has already been forwarded to the
	// upstream: the upstream connection may therefore carry an identity. See
	// refuseBindLocally.
	upstreamBound bool

	// closeFn tears down the client and upstream connections (set by handleConn).
	closeFn func()
}

// setUpstream publishes the upstream connection.
func (h *connHandler) setUpstream(c net.Conn) {
	h.upMu.Lock()
	h.upstream = c
	h.upMu.Unlock()
}

// upstreamConn returns the upstream connection, or nil if it is not open.
func (h *connHandler) upstreamConn() net.Conn {
	h.upMu.Lock()
	defer h.upMu.Unlock()
	return h.upstream
}

// ensureUpstream opens the upstream connection on first need.
//
// The dial is LAZY. A systematic dial at accept time turned every incoming
// socket into an upstream connection — including a connection that does not
// even complete a TLS handshake, or whose local bind is refused before any
// exchange with the directory.
func (h *connHandler) ensureUpstream() (net.Conn, error) {
	h.dialOnce.Do(func() {
		defer close(h.ready)

		up, err := h.p.dialUpstream(h.ctx)
		if err != nil {
			h.dialErr = err
			h.p.log.Error("upstream connection failed",
				"upstream", h.p.upstreamDesc, "error", err)
			return
		}
		h.setUpstream(up)
	})
	return h.upstreamConn(), h.dialErr
}

// forward relays bytes verbatim to the upstream (§4.2).
func (h *connHandler) forward(raw []byte) error {
	up, err := h.ensureUpstream()
	if err != nil {
		return err
	}
	_, err = up.Write(raw)
	return err
}

// refuseBindLocally synthesizes a bind failure response to the client.
//
// If a bind has already been forwarded to the upstream, the upstream connection
// still carries the previous identity. The synthesized response tells the
// client it is no longer bound, but the upstream knows nothing of it: the
// client would therefore keep working with the rights of the previous identity
// while believing itself anonymous. We cannot re-anonymize the upstream without
// rewriting its state, so we close the connection rather than lie about the
// state (§4.1).
//
// mustClose forces the closure even without an upstream identity: RFC 4511
// §4.2.1 requires closing the connection after a malformed PDU or an
// unsupported protocol version.
func (h *connHandler) refuseBindLocally(messageID int, code ResultCode, diagnostic string, mustClose bool) {
	hadUpstreamIdentity := h.upstreamBound
	h.upstreamBound = false

	h.writeBindResult(messageID, code, diagnostic)

	if !hadUpstreamIdentity && !mustClose {
		return
	}
	if hadUpstreamIdentity {
		h.p.log.Warn("bind refused after a bind already forwarded to the upstream: "+
			"closing the connection so as not to keep the upstream identity",
			"messageID", messageID, "resultCode", code)
	}
	h.closeFn()
}

// writeToClient writes a whole LDAP message to the client, under the lock.
func (h *connHandler) writeToClient(b []byte) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := h.client.Write(b)
	return err
}

// handleConn runs the two relay goroutines against each other, then tears down
// (no goroutine leak).
func (p *Proxy) handleConn(ctx context.Context, client net.Conn) {
	h := &connHandler{
		p:      p,
		ctx:    ctx,
		client: client,
		ready:  make(chan struct{}),
		done:   make(chan struct{}),
	}

	var once sync.Once
	shutdown := func() {
		once.Do(func() {
			close(h.done)
			_ = client.Close()
			if up := h.upstreamConn(); up != nil {
				_ = up.Close()
			}
		})
	}
	h.closeFn = shutdown

	var relayWG sync.WaitGroup
	relayWG.Add(2)
	// upstream → client: message-by-message relay (see upstreamToClient).
	go func() {
		defer relayWG.Done()
		h.upstreamToClient()
		shutdown()
	}()
	// client → upstream: bind substitution, verbatim relay of the rest (§4.1).
	go func() {
		defer relayWG.Done()
		h.clientToUpstream()
		shutdown()
	}()

	// Context cancellation → we close everything, which unblocks both relays.
	finished := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			shutdown()
		case <-finished:
		}
	}()

	relayWG.Wait()
	close(finished)
}

// upstreamToClient relays to the client what the directory responds.
//
// An LDAP message is read IN FULL (BER framing, §4.3) then written in a single
// operation under the lock. An io.Copy would release the lock between two 32
// KiB fragments: a synthesized response (§4.1) could then insert itself in the
// middle of a message being relayed, and the client would read that response as
// the continuation of the previous message — a permanent desynchronization of
// its decoder.
//
// Accepted consequence: an upstream message is bounded by maxMessageSize, like
// a client request. 64 MiB remains well above OpenLDAP's limits
// (sockbuf_max_incoming is 256 KiB by default).
func (h *connHandler) upstreamToClient() {
	// We wait for clientToUpstream to have opened the upstream connection (or
	// failed): it is the one that triggers the dial, not us.
	select {
	case <-h.ready:
	case <-h.done:
		return
	}
	if h.dialErr != nil {
		return
	}
	up := h.upstreamConn()
	if up == nil {
		return
	}

	r := bufio.NewReader(up)
	for {
		env, err := ReadMessage(r)
		if err != nil {
			if err != io.EOF && !errors.Is(err, net.ErrClosed) {
				h.p.log.Debug("end of upstream read", "error", err)
			}
			return
		}
		if err := h.writeToClient(env.Raw); err != nil {
			h.p.log.Debug("client write failed", "error", err)
			return
		}
	}
}

// clientToUpstream reads one LDAPMessage at a time and decides the handling.
func (h *connHandler) clientToUpstream() {
	r := bufio.NewReader(h.client)

	// Deadline only on the first message. Once past it, we cancel it: a long
	// search leaves the client mute without that having to cut the connection.
	_ = h.client.SetReadDeadline(time.Now().Add(firstMessageTimeout))

	for {
		env, err := ReadMessage(r)
		if err != nil {
			if err != io.EOF && !errors.Is(err, net.ErrClosed) {
				h.p.log.Debug("end of client read", "error", err)
			}
			return
		}
		_ = h.client.SetReadDeadline(time.Time{})

		switch env.OpTag {
		case opBindRequest:
			if err := h.handleBind(env); err != nil {
				return
			}
		case opExtendedRequest:
			if err := h.handleExtended(env); err != nil {
				return
			}
		case opUnbindRequest:
			// Unbind: relayed verbatim, then we close the upstream write direction.
			if err := h.forward(env.Raw); err != nil {
				return
			}
			if cw, ok := h.upstreamConn().(interface{ CloseWrite() error }); ok {
				_ = cw.CloseWrite()
			}
			return
		default:
			// Everything else (searches, modifications, controls, paged
			// results…) is relayed byte for byte.
			if err := h.forward(env.Raw); err != nil {
				return
			}
		}
	}
}

// handleBind applies the identity substitution (§4.1).
func (h *connHandler) handleBind(env *Envelope) error {
	bind, err := ParseBindRequest(env.OpContent)
	if errors.Is(err, ErrNotSimpleBind) {
		// SASL: out of scope, relayed as is (no secret leaks).
		h.p.log.Debug("SASL bind relayed verbatim", "messageID", env.MessageID)
		h.upstreamBound = true
		return h.forward(env.Raw)
	}
	if err != nil {
		// Unreadable PDU: RFC 4511 §4.2.1 requires protocolError and closing
		// the connection.
		h.p.log.Warn("unreadable BindRequest", "messageID", env.MessageID, "error", err)
		h.refuseBindLocally(env.MessageID, ResultProtocolError, "", true)
		return nil
	}

	// §4.3: only version 3 is handled. A version 2 would otherwise be silently
	// promoted to v3 by the bind rewrite.
	if bind.Version != 3 {
		h.p.log.Warn("unsupported LDAP version",
			"version", bind.Version, "messageID", env.MessageID)
		h.refuseBindLocally(env.MessageID, ResultProtocolError, "", true)
		return nil
	}

	m := h.p.cfg.Lookup(bind.DN)
	if m == nil {
		if h.p.cfg.AllowUnmappedBind {
			h.p.log.Debug("unmapped bind relayed (allow_unmapped_bind)", "dn", bind.DN, "messageID", env.MessageID)
			h.upstreamBound = true
			return h.forward(env.Raw)
		}
		// DN absent from the mapping: refused, never forwarded (§4.1). We log
		// ONLY the DN, never the password.
		//
		// We deliberately consume a bcrypt here: without it, this refusal would
		// answer in a few microseconds whereas "invalid password" takes tens of
		// milliseconds, and the gap would make it possible to enumerate the
		// mapped DNs — exactly what §4.1 forbids.
		_ = bcrypt.CompareHashAndPassword(h.p.dummyHash, bind.Password)

		h.p.log.Info("unmapped bind refused", "dn", bind.DN, "messageID", env.MessageID)
		h.refuseBindLocally(env.MessageID, ResultInvalidCredentials, "", false)
		return nil
	}

	// Local verification of the dummy password (bcrypt, slow by construction).
	if bcrypt.CompareHashAndPassword([]byte(m.LocalPasswordBcrypt), bind.Password) != nil {
		h.p.log.Info("invalid local password", "dn", bind.DN, "messageID", env.MessageID)
		// Response STRICTLY identical to the "unmapped DN" case above: same
		// code, same empty matchedDN, same empty diagnostic. The two refusals
		// are thus indistinguishable (§4.1), which prevents enumeration of the
		// mapped accounts.
		h.refuseBindLocally(env.MessageID, ResultInvalidCredentials, "", false)
		return nil
	}

	// Success: we rebuild the BindRequest with the real upstream pair, keeping
	// the messageID. We NEVER forward the client's bytes.
	out, err := EncodeBindRequest(env.MessageID, m.RemoteDN, []byte(m.RemotePassword))
	if err != nil {
		h.p.log.Error("failed to encode substituted bind", "error", err)
		h.refuseBindLocally(env.MessageID, ResultUnwillingToPerform, "internal proxy error", true)
		return nil
	}

	h.p.log.Info("local bind substituted",
		"local_dn", bind.DN, "upstream_dn", m.RemoteDN, "messageID", env.MessageID)
	h.upstreamBound = true

	// The upstream BindResponse will be relayed verbatim by the upstream →
	// client goroutine: we synthesize nothing on success (§4.1).
	return h.forward(out)
}

// handleExtended refuses StartTLS locally, relays any other operation (§3).
func (h *connHandler) handleExtended(env *Envelope) error {
	name, err := ParseExtendedRequestName(env.OpContent)
	if err != nil {
		h.p.log.Warn("unreadable ExtendedRequest, relayed verbatim", "messageID", env.MessageID, "error", err)
		return h.forward(env.Raw)
	}

	if name == OIDStartTLS {
		// StartTLS would impose a mid-stream protocol change, with an already
		// buffered reader. We refuse cleanly (§3).
		h.p.log.Info("StartTLS refused: LDAPS required", "messageID", env.MessageID)
		resp, err := EncodeExtendedResponse(env.MessageID, ResultUnwillingToPerform, "StartTLS not supported, use LDAPS")
		if err != nil {
			h.p.log.Error("failed to encode StartTLS response", "error", err)
			return nil
		}
		if err := h.writeToClient(resp); err != nil {
			h.p.log.Debug("client write failed", "error", err)
			return err
		}
		return nil
	}

	// Any other extended operation (e.g. WhoAmI) is relayed verbatim.
	return h.forward(env.Raw)
}

// writeBindResult synthesizes a local BindResponse to the client.
func (h *connHandler) writeBindResult(messageID int, code ResultCode, diagnostic string) {
	resp, err := EncodeBindResponse(messageID, code, diagnostic)
	if err != nil {
		h.p.log.Error("failed to encode BindResponse", "error", err)
		return
	}
	if err := h.writeToClient(resp); err != nil {
		h.p.log.Debug("client write failed", "error", err)
	}
}
