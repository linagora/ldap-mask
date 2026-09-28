# AGENTS.md

Read this first. Follow it exactly. Skipping steps will break CI,
block merges, corrupt the codebase or make the maintainers unhappy.

## Presentation

- ldap-mask is an LDAP proxy that **substitutes a fictitious local
  identity for a real upstream one**: the client binds with a local
  DN/password, the proxy verifies it locally and rebinds upstream with
  the real credentials. Everything else is relayed verbatim.

- Written in **Go**, one `main` package, no internal packages. The
  standard library does the heavy lifting; the only dependencies are
  `go-asn1-ber` (encoding the messages we synthesise), `x/crypto/bcrypt`
  and `yaml.v3`. Adding a dependency needs a reason.

- BER **decoding** is hand-written in `ber.go`, deliberately: it must
  preserve the client's original bytes. Encoding uses `asn1-ber`.

- Build with `go build .`. Test with `go test ./...`, or
  `go test -race ./...` before submitting.

- The integration tests are behind the `e2e` build tag and need a real
  directory plus environment variables — see
  `.github/workflows/e2e.yml`. They skip themselves without
  `LDAP_MASK_E2E=1`, so `go test ./...` stays green.

## Code comments

- Comment only unconventional or tricky code: a non-obvious
  constraint, a workaround, a subtle ordering, a security-relevant
  detail.
- Never paraphrase the code. If the comment restates what the next
  lines do, delete it.
- No project history in comments: no "used to", "since 0.6", "replaced
  the old check". Exception: rare cases where the history is required
  to understand why the implementation looks the way it does.
- No design rationale in build files, scripts or config files. Link
  to the relevant documentation instead, if anything.
- When you change code, update or remove the comments around it. An
  obsolete comment is worse than no comment: it misleads reviewers,
  auditors and agents.

## Documentation

- Document architecture choices and feature implementation once, in
  **`DESIGN.md`**. It is the design reference for this project.
- Record significant decisions in a single place; do not duplicate
  them in comments, changelog or commits.
- Elsewhere, reference that document rather than repeating its
  content.
- `README.md` is for users: how to build, configure and run. It does
  not restate the design.

## Specific files

### DESIGN.md

- Audience: implementers and operators who must judge whether the
  proxy is safe to deploy in their context.
- §6 lists what the proxy does **not** protect. It is the part to
  re-read before deploying and must stay honest. Do not soften it, and
  do not describe a limitation as theoretical if it is not.
- Section numbers are referenced from the README and from code
  comments. Renumbering breaks links: do not renumber.
- When an implementation detail contradicts the design, fix whichever
  is wrong — do not leave the contradiction standing.

### README.md

- Audience: someone deciding whether to use the tool, then using it.
- The comparison tables and the cleartext/TLS matrix must match the
  actual behaviour of `config.go`. Verify before editing them.

## Git commit messages

- Audience: developers.
- A concise subject line, then a short body explaining why when it is
  not obvious. Not a diary, not a copy of the documentation.
- Reference issues/PRs here — this is where history belongs.

## Before submitting

- [ ] `gofmt -l .` prints nothing.
- [ ] `go vet ./...` and `go vet -tags=e2e ./...` are clean.
- [ ] `go test -race ./...` passes.
- [ ] Every comment explains something non-obvious and still true.
- [ ] No history, issue numbers or rationale in comments or build
      files.
- [ ] Design changes are documented once, in `DESIGN.md`.
- [ ] Commit messages are concise and explain why.
