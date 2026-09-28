# ldap-mask — design

> Status: **implemented**. This document remains the design reference; it was
> amended where the implementation had the final say — §4.2 (relay message by
> message rather than `io.Copy`) and §6.4 (both legs may be cleartext, each
> reported at startup).
> Date: 2026-09-28

## 1. Objective

An LDAP proxy in front of **a single destination OpenLDAP directory**.

The client (test app, agent, throwaway tool) binds with a **local and
fictitious** DN/password pair. The proxy verifies this password locally, then
rebinds upstream with the **real** DN and the **real** password, stored in its
own configuration.

Goal: give admin access to a test app without revealing the real admin account
to it.

## 2. The principle that matters: substitution, not rewriting

Two very different things, often confused:

| Approach | What the client knows | Verdict |
|---|---|---|
| **DN rewriting** | The real password, an alias DN | ❌ Hides nothing — the secret is still on the client side |
| **Identity substitution** | A fictitious DN *and* password | ✅ What we want |

It is this criterion that rules out most existing solutions
(`slapd back-ldap` + `idassert-bind` performs identity delegation, not
substitution: the client DN must exist upstream).

## 3. Scope

### v1 — in scope

- Interception of the **simple bind** only.
- **Everything else relayed byte for byte** (searches, modifications, controls,
  paged results, extended operations).
- Listens on **LDAPS** or **cleartext LDAP**, chosen via the scheme of
  `listen`.
- Upstream over `ldap://` or `ldaps://`.
- Several local → remote mappings.
- Local password stored **hashed** (bcrypt).
- Remote password injected via environment variable (`${VAR}`), never
  cleartext on disk.

This is a debug tool: all **four combinations** of listener (cleartext/TLS) and
upstream (cleartext/TLS) must be usable. TLS is available on both sides, never
forced.

### v1 — out of scope (and why)

| Out of scope | Reason |
|---|---|
| **Client-side StartTLS** | Forces a protocol change mid-stream, with an already buffered reader: the bytes already read would have to be re-injected before the TLS switchover. Listening directly over `ldaps://` does the same job without that problem. Refused cleanly (`unwillingToPerform`), including — and especially — on a cleartext listener, where the request is actually reachable |
| **SASL** | Relayed as-is, but not substituted. The SASL client uses its own credentials — no secret leaks |
| **Operation restriction** | See §6: an admin alias *is* an admin. If the need is to limit the blast radius, that is a separate layer |
| **Referrals / Root DSE / WhoAmI rewriting** | Known and documented leaks, see §6 |

## 4. How it works

### 4.1 A substituted bind

```
client ──BindRequest(cn=test-admin,dc=test / "hunter2")──▶ proxy
                                                            │
                                        lookup in the mapping
                                                            │
                                      bcrypt("hunter2") ✓ / ✗
                                                            │
                              proxy ──BindRequest(cn=admin,dc=… / real pw)──▶ OpenLDAP
                                                            │
client ◀──────── BindResponse (relayed as-is) ───────┘
```

Design points:

- The proxy **rebuilds** the `BindRequest` with `ber` and the same `messageID`.
- The upstream `BindResponse` is **relayed verbatim** — a response is
  synthesized only in local failure cases.
- **Indistinguishable refusals**: unknown DN and wrong password both return
  `invalidCredentials` (49). Otherwise the mapped accounts can be enumerated.

  The indistinguishability must be **temporal too**: comparing the password
  costs a bcrypt, not a table lookup. The refusal for an unknown DN therefore
  also consumes a bcrypt (on a dummy hash); otherwise measuring the response
  time would be enough to enumerate the mapped DNs.

- **Version checked**: only v3 is handled (§4.3). Otherwise a v2 would be
  silently promoted to v3 by the bind rewriting.

- **Bind controls dropped**: the substituted `BindRequest` is rebuilt, so any
  controls attached to the original bind are not forwarded. This is the
  counterpart of "rebuilt"; worth noting if a client sends any.
- A failed bind **resets the state**: the connection becomes anonymous again
  (RFC 4511 §4.2.1).
- `allow_unmapped_bind: false` by default: a DN absent from the mapping is
  refused, not forwarded.

### 4.2 After the bind: pure relay

Two goroutines per client connection:

- **client → upstream**: read one message, inspect the envelope. If the tag is
  `0x60` (BindRequest), §4.1 handling; otherwise write the **original bytes**
  to the upstream.
- **upstream → client**: read one **whole** message (same BER framing as
  §4.3), then write its **original bytes**. Nothing is rewritten.

  This is deliberately not an `io.Copy`: `io.Copy` releases the lock between
  two 32 KiB fragments, and a synthesized response (§4.1) could then slip
  **into the middle** of a message being relayed. The client would read that
  response as the continuation of the previous message, and its BER decoder
  would be permanently desynchronized. So framing also serves the integrity of
  the stream, not just reading.

  Accepted trade-off: an upstream message is bounded by the same size as a
  client request (64 MiB), whereas an `io.Copy` was unbounded. The limit
  remains far above OpenLDAP's (`sockbuf_max_incoming` is 256 KiB by default).

One **upstream connection per client connection**: the *bound* state is a
connection state, it cannot be shared through a pool. It is opened **lazily**,
on the first message to relay — otherwise every incoming socket, including a
connection that does not even complete a TLS handshake or whose bind is
refused locally, would open a connection to the directory.

A mutex protects writes to the client, since locally synthesized responses
(§4.1) and the relayed stream (§4.2) write to the same socket. It is taken
**for an entire message**, never for a fragment: that is what makes the relay
above atomic from the client's point of view.

A timeout bounds the wait for the **first** client message (a socket opened
then left silent does not tie up a goroutine indefinitely). There is no
inactivity timeout afterwards: a long search legitimately leaves the client
silent while the results arrive.

### 4.3 BER decoding

The outer TLV is read to know the exact length of the message:

- `LDAPMessage` is always a `SEQUENCE` (`0x30`) in **definite form**. The
  indefinite form (`0x80`) is forbidden by RFC 4511 §5.1 → rejected.
- Short length (< 128) or long length (`0x80 | n` then `n` bytes).
- Then `messageID` (INTEGER `0x02`) and the operation tag are read.

The content is only descended into for `0x60`:

```
BindRequest ::
  version  INTEGER        (expected: 3)
  name     OCTET STRING   (the DN)
  auth     CHOICE {
    simple  [0] OCTET STRING   ← 0x80, what we know how to handle
    sasl    [3] SEQUENCE       ← 0xA3, relayed as-is
  }
```

Everything else is treated as opaque, which guarantees fidelity: no
re-encoding, hence no risk of altering an exotic control or a binary attribute.

## 5. Configuration

```yaml
# The scheme decides the listener mode, and it is MANDATORY:
#   ldaps:// → TLS terminated on the proxy (tls: required)
#   ldap://  → cleartext (tls: ignored)
listen: "ldaps://0.0.0.0:1636"

tls:
  cert_file: /certs/proxy.crt
  key_file:  /certs/proxy.key

upstream:
  url: "ldaps://ldap.internal:636"     # or ldap://
  ca_file: /certs/internal-ca.crt
  insecure_skip_verify: false          # false, deliberately

mappings:
  - local_dn: "cn=test-admin,dc=test"
    local_password_bcrypt: "$2a$10$..."     # generated by `ldap-mask -hash`
    remote_dn: "cn=admin,dc=example,dc=com"
    remote_password: "${LDAP_ADMIN_PASSWORD}"

allow_unmapped_bind: false
```

- `${VAR}` is resolved from the environment at load time.
- The local DN serves as the lookup key, normalized (lowercased, spaces around
  commas removed). **Accepted approximation**: this is not a real DN parser
  (escaping, `\+`, quotes). To be replaced with a correct parser if the need
  arises.

## 6. Security — what the proxy does **not** protect

This is the part to re-read before deploying.

1. **A substituted admin identity is an admin.** The proxy hides the password,
   not the capability. An app that does a mass `delete` will do just as much
   through the substituted identity. If the goal is to limit the blast radius,
   an operation / subtree allowlist is needed *in addition*.

2. **The proxy must be out of the agent's reach.** If the agent has a shell on
   the same machine, it reads the config file and retrieves the real password.
   Hence: a separate container, secret injected via environment variable, real
   password never written on disk.

3. **Known leaks, not addressed in v1:**
   - `Root DSE` → `namingContexts` reveals the directory's real suffix.
   - Extended operation `WhoAmI` (`1.3.6.1.4.1.4203.1.11.3`) → returns the real
     DN of the bound identity.
   - The `SearchResultReference` (referrals) point to the real directory: a
     client that follows them **bypasses the proxy**.

   None of them reveals the *password*, but all three reveal the real DN.
   Interceptable in v2 (§8).

4. **Encrypt both legs when possible.** Client → proxy over LDAPS, proxy →
   upstream over TLS: the real password travels on the upstream leg.

   Both may be cleartext — this is a debug tool, and forcing TLS would have
   made it unusable on a test bench. But those are then the only cases where a
   password — the real one, on the upstream side — crosses the network
   unencrypted. The proxy **logs a `WARN` at startup for each cleartext leg**:
   the operator must not be able to ignore it.

   The only setting that remains **forbidden by default** is
   `insecure_skip_verify`, which does not weaken encryption but the *identity
   verification* of the upstream (see `config.go` and `LDAP_MASK_ALLOW_INSECURE`).

5. **Anti-bruteforce**: bcrypt is slow by construction, which bounds the rate.
   No failure counter and no lockout in v1 — to be added if the proxy is
   exposed beyond a trusted network.

## 7. File tree and dependencies

```
main.go      flags, config loading, listener, TLS
config.go    structs + loading + ${ENV} expansion
ber.go       BER framing, envelope, BindRequest parsing
proxy.go     per-connection loop, relay, substitution
hash.go      bcrypt hash generation subcommand
README.md
Dockerfile
LICENSE      GNU AGPL-3.0
DESIGN.md    this file
```

Tests and continuous integration:

```
*_test.go                 unit tests (net.Pipe for the proxy, malformed
                          inputs, equality of refusals, non-regression)
e2e_test.go  (-tags=e2e)  integration against a real OpenLDAP, driven by real
                          clients (ldapwhoami, ldapsearch)
.github/workflows/ci.yml     gofmt, vet, golangci-lint, -race tests, Docker build
.github/workflows/e2e.yml    integration: OpenLDAP container + e2e tests
.github/workflows/release.yml builds and publishes the release on a v* tag
```

Dependencies:

| Module | Role |
|---|---|
| `github.com/go-asn1-ber/asn1-ber` | BER encoding/decoding |
| `golang.org/x/crypto/bcrypt` | local password hashing |
| `gopkg.in/yaml.v3` | configuration |

Deliberately **no** `go-ldap/ldap`: no high-level LDAP client is used on the
upstream side, since the bytes are written ourselves. One dependency less.

### Build and CI notes

`AGENTS.md` forbids design rationale in build files and configuration, so the
reasons live here.

**Docker** (`Dockerfile`). `CGO_ENABLED=0` produces a static binary.
`gcr.io/distroless/static-debian12` rather than bare `scratch`, because
distroless ships `/etc/ssl/certs` — without it the upstream TLS handshake fails
at the first connection. The Go builder image is pinned **exactly**
(`golang:1.26.8`, not `golang:1.26`) because `go.mod` requires that patch
version: a builder on an older patch would download a toolchain mid-build,
which breaks the moment the build has no network. The container runs as
`nonroot` (uid 65532), so the mounted TLS private key must be readable by that
uid — see the README. `go.mod`/`go.sum` are copied before the sources so the
dependency layer stays cached across source edits.

**Linting** (`.golangci.yml`). The default "standard" set plus `misspell` in
**US** locale. The set is deliberately small so CI does not break when a linter
is renamed or removed upstream. `misspell` earns its place now that the
codebase is English; it is what keeps `behaviour`/`cancelled`-style spellings
out.

**Lint action version** (`ci.yml`). `golangci/golangci-lint-action` must stay on
**v9 or later**: v6 predates golangci-lint v2 and fails at install time when
handed a v2 binary. The linter itself is pinned to an exact version so a broken
upstream release cannot turn CI red without a decision.

**Default branch** (`ci.yml`). The concurrency rule cancels superseded runs on
every ref *except* the default branch, derived from
`github.event.repository.default_branch` rather than hardcoded — this repository
uses `master`, but that is a setting, not a fact about the code.

**Releases** (`release.yml`). A `v*` tag triggers a cross-compiled build
(linux/darwin, amd64/arm64), `-X main.version` set from the tag so `-version`
and the startup banner report it, a `SHA256SUMS` file, and a published GitHub
release with generated notes. The workflow re-runs the unit tests and refuses a
tag that does not look like `vMAJOR.MINOR.PATCH`, so a mistyped tag fails before
anything is published.

The machine already has Go 1.26.8, Docker 28.5.2 and OpenLDAP 2.6.15 clients
(`ldapsearch`, `ldapwhoami`).

## 8. Follow-up

- Rewriting `Root DSE`, `WhoAmI`, referrals (§6.3).
- Operation / subtree allowlist, to turn "admin" into "admin on this
  perimeter".
- Client-side StartTLS.
- Structured audit log: who (local DN) did what (operation, target).
- Bind failure counter + temporary lockout.
- A compliant DN parser instead of the approximate normalization.

## 9. Test plan

A throwaway OpenLDAP directory in a container, an admin account, then:

1. `ldapwhoami` with the **local** pair → must answer OK. *(It will return the
   real DN: this is the expected §6.3 leak, not a bug.)*
2. `ldapsearch` with the local pair → must return the normal entries.
3. Bind with the correct local DN but a **wrong** password → `49`.
4. Bind with an **unmapped DN** → `49`, indistinguishable from the previous
   case.
5. The **real** password must **never** be accepted on the local DN.
6. `ldapsearch` with paged results → verify that the control passes through.
7. Build the stripped static binary, then run it in a container to validate
the image (CA bundle, config, `${ENV}`).
