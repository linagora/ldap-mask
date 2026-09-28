// main.go — entry point: flags, LDAPS listener, graceful shutdown.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

// version can be overridden at build time:
//
//	go build -ldflags "-X main.version=1.2.3"
var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "ldap-mask: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	// We extract --hash ourselves to accept both `--hash` (password read on
	// stdin) and `--hash=<password>`.
	hashMode, hashValue, rest := extractHashFlag(os.Args[1:])

	fs := flag.NewFlagSet("ldap-mask", flag.ExitOnError)
	fc := registerFlags(fs)
	showVersion := fs.Bool("version", false, "print the version and exit")
	fs.Usage = func() { printUsage(fs) }
	_ = fs.Parse(rest)

	// No positional argument is expected. Ignoring them silently is precisely
	// what caused hashing standard input instead of the supplied password: we
	// refuse explicitly rather than guess.
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected positional argument %q (options start with \"--\")", fs.Arg(0))
	}

	if *showVersion {
		fmt.Println("ldap-mask " + version)
		return nil
	}

	if hashMode {
		if hashValue != "" {
			fmt.Fprintln(os.Stderr,
				"warning: a password passed as an argument is visible in the process "+
					"list (ps) and in the shell history; prefer \"ldap-mask --hash\" "+
					"and typing on standard input.")
		}
		password, err := readPasswordForHash(hashValue)
		if err != nil {
			return err
		}
		h, err := HashPassword(password)
		if err != nil {
			return err
		}
		fmt.Println(h)
		return nil
	}

	cfg, literalPassword, err := buildConfig(fs, fc)
	if err != nil {
		return err
	}
	return serve(cfg, literalPassword)
}

// printUsage replaces fs.PrintDefaults, which spells every option with a
// single dash; package flag accepts both spellings and we document "--".
// --hash is stripped from os.Args before fs sees it (it has to accept a bare
// "--hash" as well as "--hash=VALUE"), so it is appended by hand.
func printUsage(fs *flag.FlagSet) {
	out := fs.Output()
	_, _ = fmt.Fprint(out, `Usage:
  ldap-mask --config FILE [options]
  ldap-mask --listen URL --upstream URL MAPPING [options]
  ldap-mask --hash [PASSWORD]

MAPPING takes one of two forms, which can be combined:
  --local-dn DN --local-password PW --remote-dn DN --remote-password PW
	one mapping, without JSON; --local-password-bcrypt HASH replaces
	--local-password
  --map JSON
	one mapping per occurrence, repeatable, e.g.
	--map '{"local_dn":"cn=test-admin,dc=test","local_password":"hunter2",
	        "remote_dn":"cn=admin,dc=example,dc=com","remote_password":"s3cret"}'
Either form replaces the mappings of the configuration file.

Options:
`)
	fs.VisitAll(func(f *flag.Flag) {
		arg, usage := flag.UnquoteUsage(f)
		if arg != "" {
			arg = " " + arg
		}
		_, _ = fmt.Fprintf(out, "  --%s%s\n\t%s\n", f.Name, arg, strings.ReplaceAll(usage, "\n", "\n\t"))
	})
	_, _ = fmt.Fprintf(out, "  --hash [PASSWORD]\n"+
		"\tgenerate a bcrypt hash of PASSWORD and exit; without a value, the\n"+
		"\tpassword is read on standard input\n")
}

// flagConfig holds the command-line configuration options.
type flagConfig struct {
	config        string
	listen        string
	tlsCert       string
	tlsKey        string
	upstream      string
	upstreamCA    string
	insecureSkip  bool
	allowUnmapped bool
	maps          mapList
	mapFlags      mapEntry
}

// registerFlags declares the configuration flags on fs and returns their
// targets. --config defaults to the empty string: no file is read unless asked
// for, so the proxy can run on flags alone.
func registerFlags(fs *flag.FlagSet) *flagConfig {
	fc := &flagConfig{}
	fs.StringVar(&fc.config, "config", "",
		"path to the YAML configuration file; \"\" reads no file, \"-\" reads it from standard input")
	fs.StringVar(&fc.listen, "listen", "",
		"listener URL, e.g. \"ldaps://0.0.0.0:1636\" (scheme mandatory: ldap or ldaps)")
	fs.StringVar(&fc.tlsCert, "tls-cert", "", "TLS certificate presented to clients (ldaps:// listener only)")
	fs.StringVar(&fc.tlsKey, "tls-key", "", "private key of --tls-cert")
	fs.StringVar(&fc.upstream, "upstream", "", "upstream directory URL, e.g. \"ldaps://directory.internal:636\"")
	fs.StringVar(&fc.upstreamCA, "upstream-ca", "", "CA file used to verify the upstream certificate (ca_file)")
	fs.BoolVar(&fc.insecureSkip, "insecure-skip-verify", false,
		"do not verify the upstream certificate (the config-file key insecure_skip_verify needs LDAP_MASK_ALLOW_INSECURE=1, this flag does not)")
	fs.BoolVar(&fc.allowUnmapped, "allow-unmapped-bind", false,
		"relay a bind whose DN is not in the mappings instead of refusing it")
	fs.Var(&fc.maps, "map",
		"local → remote mapping as a `JSON` object, repeatable (see MAPPING above)")
	fs.StringVar(&fc.mapFlags.LocalDN, "local-dn", "",
		"local DN of the mapping given without JSON (see MAPPING above)")
	fs.Func("local-password", "cleartext local `password` of the --local-dn mapping", func(v string) error {
		fc.mapFlags.LocalPassword = &v
		return nil
	})
	fs.Func("local-password-bcrypt", "bcrypt `hash` of the local password of the --local-dn mapping", func(v string) error {
		fc.mapFlags.LocalPasswordBcrypt = &v
		return nil
	})
	fs.StringVar(&fc.mapFlags.RemoteDN, "remote-dn", "", "real DN of the --local-dn mapping; ${VAR} is expanded")
	fs.StringVar(&fc.mapFlags.RemotePassword, "remote-password", "",
		"real password of the --local-dn mapping; ${VAR} is expanded")
	return fc
}

// configFlagNames lists the flags that configure the proxy, so buildConfig can
// tell "nothing was configured" from a deliberate configuration.
var configFlagNames = []string{
	"listen", "tls-cert", "tls-key", "upstream", "upstream-ca",
	"insecure-skip-verify", "allow-unmapped-bind", "map",
	"local-dn", "local-password", "local-password-bcrypt", "remote-dn", "remote-password",
}

// mapFlagNames are the flags that describe one mapping without --map's JSON.
var mapFlagNames = []string{
	"local-dn", "local-password", "local-password-bcrypt", "remote-dn", "remote-password",
}

// buildConfig assembles the configuration: the file first (if --config was
// given), then only the flags explicitly present on the command line. The
// returned bool reports whether a password arrived literally on the command
// line (see parseMappings), for the single startup WARN in serve.
//
// Only the flags actually SET override the file. Inferring "was it set?" from a
// zero value would make it impossible to override a file's true with an explicit
// --insecure-skip-verify=false, or to empty out a field.
func buildConfig(fs *flag.FlagSet, fc *flagConfig) (*Config, bool, error) {
	set := make(map[string]bool)
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })

	if !configured(set, fc) {
		return nil, false, errors.New("no configuration: pass --config PATH (or --config - to read " +
			"it from standard input), or configure the proxy directly with the " +
			"command-line flags (--listen, --upstream, --map, …)")
	}

	cfg := &Config{}
	if fc.config != "" {
		loaded, err := parseConfig(fc.config)
		if err != nil {
			return nil, false, err
		}
		cfg = loaded
	}

	if set["listen"] {
		cfg.Listen = fc.listen
	}
	if set["tls-cert"] {
		cfg.TLS.CertFile = fc.tlsCert
	}
	if set["tls-key"] {
		cfg.TLS.KeyFile = fc.tlsKey
	}
	if set["upstream"] {
		cfg.Upstream.URL = fc.upstream
	}
	if set["upstream-ca"] {
		cfg.Upstream.CAFile = fc.upstreamCA
	}
	if set["insecure-skip-verify"] {
		cfg.Upstream.InsecureSkipVerify = fc.insecureSkip
	}
	if set["allow-unmapped-bind"] {
		cfg.AllowUnmappedBind = fc.allowUnmapped
	}
	literalPassword := false
	// --map and the single-mapping flags together replace the file's mappings
	// list wholesale (§5); they never append to it.
	var mappings []Mapping
	if set["map"] {
		m, literal, err := parseMappings(fc.maps)
		if err != nil {
			return nil, false, err
		}
		mappings = m
		literalPassword = literal
	}
	if anySet(set, mapFlagNames) {
		m, literal, err := buildMapping(fc.mapFlags, "--local-dn mapping", flagKeys)
		if err != nil {
			return nil, false, err
		}
		mappings = append(mappings, m)
		literalPassword = literalPassword || literal
	}
	if mappings != nil {
		cfg.Mappings = mappings
	}

	// Guards only the file-sourced value; see DESIGN.md §6.4.
	if !set["insecure-skip-verify"] {
		if err := checkInsecureSkipVerify(cfg.Upstream.InsecureSkipVerify); err != nil {
			return nil, false, err
		}
	}

	if err := cfg.Validate(); err != nil {
		return nil, false, err
	}
	return cfg, literalPassword, nil
}

// configured reports whether any source of configuration was requested: a file
// (--config), or at least one configuration flag.
func configured(set map[string]bool, fc *flagConfig) bool {
	return fc.config != "" || anySet(set, configFlagNames)
}

func anySet(set map[string]bool, names []string) bool {
	for _, name := range names {
		if set[name] {
			return true
		}
	}
	return false
}

// mapList collects the repeatable --map values, one JSON object each.
type mapList []string

// String returns a placeholder: the raw --map values carry passwords and must
// never surface in the usage output.
func (m *mapList) String() string { return "..." }

// Set appends one occurrence.
func (m *mapList) Set(value string) error {
	*m = append(*m, value)
	return nil
}

// mapEntry is the JSON object of one --map occurrence (DESIGN.md §5). The local
// password fields are pointers so that "given but empty" is distinguishable
// from "absent".
type mapEntry struct {
	LocalDN             string  `json:"local_dn"`
	LocalPassword       *string `json:"local_password"`
	LocalPasswordBcrypt *string `json:"local_password_bcrypt"`
	RemoteDN            string  `json:"remote_dn"`
	RemotePassword      string  `json:"remote_password"`
}

// mappingKeys names the fields of a mapEntry as the user wrote them, so an
// error points at the JSON key of --map or at the flag actually typed.
type mappingKeys struct {
	localDN, localPassword, localPasswordBcrypt, remoteDN, remotePassword string
}

var (
	jsonKeys = mappingKeys{"local_dn", "local_password", "local_password_bcrypt", "remote_dn", "remote_password"}
	flagKeys = mappingKeys{"--local-dn", "--local-password", "--local-password-bcrypt", "--remote-dn", "--remote-password"}
)

// parseMappings converts the --map JSON values into mappings (see
// buildMapping).
func parseMappings(values []string) ([]Mapping, bool, error) {
	out := make([]Mapping, 0, len(values))
	literalPassword := false
	for i, raw := range values {
		// Identify the offending --map by POSITION, never by echoing its value:
		// that value carries the passwords, and standard error is often kept
		// (CI logs, "docker logs") longer and more visibly than the process list.
		where := fmt.Sprintf("--map #%d", i+1)

		dec := json.NewDecoder(strings.NewReader(raw))
		dec.DisallowUnknownFields()
		var e mapEntry
		if err := dec.Decode(&e); err != nil {
			return nil, false, fmt.Errorf("%s: invalid JSON: %w", where, err)
		}
		if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
			return nil, false, fmt.Errorf("%s: invalid JSON: unexpected data after the object", where)
		}

		m, literal, err := buildMapping(e, where, jsonKeys)
		if err != nil {
			return nil, false, err
		}
		out = append(out, m)
		literalPassword = literalPassword || literal
	}
	return out, literalPassword, nil
}

// buildMapping validates one mapping given on the command line, expanding
// ${VAR} in remote_dn and remote_password (DESIGN.md §5) and hashing a
// cleartext local password so handleBind only ever compares a bcrypt hash. The
// returned bool reports whether a password appeared literally on the command
// line: a cleartext local password, or a remote password not made up
// exclusively of ${VAR} references.
func buildMapping(e mapEntry, where string, k mappingKeys) (Mapping, bool, error) {
	// The local DN is not a secret: naming it makes the message actionable
	// without quoting a password.
	if dn := strings.TrimSpace(e.LocalDN); dn != "" {
		where = fmt.Sprintf("%s (local_dn %q)", where, dn)
	}
	if strings.TrimSpace(e.LocalDN) == "" {
		return Mapping{}, false, fmt.Errorf("%s: %s is required", where, k.localDN)
	}
	if strings.TrimSpace(e.RemoteDN) == "" {
		return Mapping{}, false, fmt.Errorf("%s: %s is required", where, k.remoteDN)
	}
	if e.RemotePassword == "" {
		return Mapping{}, false, fmt.Errorf("%s: %s is required", where, k.remotePassword)
	}
	if e.LocalPassword == nil && e.LocalPasswordBcrypt == nil {
		return Mapping{}, false, fmt.Errorf("%s: exactly one of %s or %s is required",
			where, k.localPassword, k.localPasswordBcrypt)
	}
	if e.LocalPassword != nil && e.LocalPasswordBcrypt != nil {
		return Mapping{}, false, fmt.Errorf("%s: %s and %s are mutually exclusive",
			where, k.localPassword, k.localPasswordBcrypt)
	}

	literalPassword := e.LocalPassword != nil || envVarRe.ReplaceAllString(e.RemotePassword, "") != ""

	remoteDN, err := expandEnv(e.RemoteDN)
	if err != nil {
		return Mapping{}, false, fmt.Errorf("%s: %s: %w", where, k.remoteDN, err)
	}
	remotePassword, err := expandEnv(e.RemotePassword)
	if err != nil {
		return Mapping{}, false, fmt.Errorf("%s: %s: %w", where, k.remotePassword, err)
	}

	m := Mapping{
		LocalDN:        e.LocalDN,
		RemoteDN:       remoteDN,
		RemotePassword: remotePassword,
	}
	if e.LocalPassword != nil {
		if *e.LocalPassword == "" {
			// A hash of the empty string would accept any bind without a
			// password for this DN.
			return Mapping{}, false, fmt.Errorf("%s: %s is empty", where, k.localPassword)
		}
		h, err := HashPassword(*e.LocalPassword)
		if err != nil {
			return Mapping{}, false, fmt.Errorf("%s: %w", where, err)
		}
		m.LocalPasswordBcrypt = h
	} else {
		if *e.LocalPasswordBcrypt == "" {
			return Mapping{}, false, fmt.Errorf("%s: %s is empty", where, k.localPasswordBcrypt)
		}
		m.LocalPasswordBcrypt = *e.LocalPasswordBcrypt
	}
	return m, literalPassword, nil
}

// extractHashFlag removes --hash / --hash=VALUE / --hash VALUE (or their
// single-dash spellings, which package flag accepts for every other option)
// from args and returns the hash mode, the optional value and the remaining
// arguments.
//
// The separate form "--hash <password>" is accepted. Without it, the password
// passed as an argument would be silently ignored and the hash computed on
// standard input: the user would walk away with the hash of another password,
// with not the slightest signal.
func extractHashFlag(args []string) (hashMode bool, hashValue string, rest []string) {
	rest = make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-hash" || a == "--hash":
			hashMode = true
			// We consume the following argument only if it is not a
			// flag: "--hash --config x.yaml" must keep reading the
			// password on standard input.
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				hashValue = args[i+1]
				i++
			}
		case strings.HasPrefix(a, "-hash="), strings.HasPrefix(a, "--hash="):
			hashMode = true
			hashValue = a[strings.Index(a, "=")+1:]
		default:
			rest = append(rest, a)
		}
	}
	return hashMode, hashValue, rest
}

// readPasswordForHash returns the password to hash: the explicit value,
// otherwise a line read on stdin (carriage returns stripped).
func readPasswordForHash(value string) (string, error) {
	if value != "" {
		return value, nil
	}
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return "", fmt.Errorf("reading password on stdin: %w", err)
	}
	pw := strings.TrimRight(string(data), "\r\n")
	if pw == "" {
		// Accepting the empty string would produce a hash that validates any
		// bind without a password. An empty stdin is far more often an
		// accident (dry pipe, heredoc, build step) than an intention.
		return "", errors.New("empty password on standard input: " +
			"a hash of the empty string would accept any bind without a password")
	}
	return pw, nil
}

// listenFor opens the listener described by `listen`.
//
// The scheme decides the mode: "ldaps://" terminates TLS on the proxy,
// "ldap://" serves in cleartext. Both are first-class — this is a debug tool,
// it must be able to sit on either side of a client or a directory, encrypted
// or not.
func listenFor(cfg *Config) (net.Listener, error) {
	scheme, err := cfg.ListenScheme()
	if err != nil {
		return nil, err
	}
	addr, err := cfg.ListenAddr()
	if err != nil {
		return nil, err
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listening on %q: %w", addr, err)
	}

	if scheme == "ldap" {
		return ln, nil
	}

	cert, err := tls.LoadX509KeyPair(cfg.TLS.CertFile, cfg.TLS.KeyFile)
	if err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("loading TLS certificate: %w", err)
	}
	return tls.NewListener(ln, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}), nil
}

// serve serves the validated configuration until SIGINT/SIGTERM.
// literalPassword is true when a password arrived literally on the command
// line (--map), as opposed to only through a ${VAR} reference, which is
// reported with a single warning.
func serve(cfg *Config, literalPassword bool) error {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	proxy, err := New(cfg, logger)
	if err != nil {
		return err
	}

	ln, err := listenFor(cfg)
	if err != nil {
		return err
	}

	// A password on the command line is not hidden: it sits in the process list
	// and in the shell history of a shared host.
	if literalPassword {
		logger.Warn("password passed on the command line: readable in the process list (ps) and the shell history")
	}

	// Both legs can be in cleartext (this is a debug tool), but we refuse to
	// let the operator ignore it: these are the cases where a password — the
	// real one on the upstream side — travels unencrypted.
	listenScheme, _ := cfg.ListenScheme()
	if listenScheme == "ldap" {
		logger.Warn("cleartext listener: local passwords travel unencrypted on the client → proxy leg",
			"listen", ln.Addr().String())
		if cfg.TLS.CertFile != "" {
			logger.Info("tls block: ignored, the listener is in cleartext", "listen", cfg.Listen)
		}
	}
	if cfg.UpstreamScheme() == "ldap" {
		logger.Warn("cleartext upstream: the real password travels unencrypted on the proxy → directory leg",
			"upstream", proxy.upstreamDesc)
	}

	// Weakening the upstream identity check is the other thing an operator must
	// not be able to miss: it is off by default, and turning it on disables
	// certificate verification for the leg that carries the real password.
	if cfg.Upstream.InsecureSkipVerify {
		logger.Warn("insecure_skip_verify: the upstream certificate is NOT verified, "+
			"so the proxy cannot tell the real directory from an impostor",
			"upstream", proxy.upstreamDesc)
	}

	// Startup banner: listener address and served local DNs. No password,
	// local or remote, is ever displayed.
	logger.Info("LDAP proxy starting",
		"version", version,
		"listen", cfg.Listen,
		"address", ln.Addr().String(),
		// Redacted URL: a userinfo in upstream.url must not end up here.
		"upstream", proxy.upstreamDesc,
		"allow_unmapped_bind", cfg.AllowUnmappedBind)
	for i := range cfg.Mappings {
		logger.Info("mapping loaded", "local_dn", cfg.Mappings[i].LocalDN)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := proxy.Serve(ctx, ln); err != nil {
		return err
	}
	logger.Info("clean proxy shutdown")
	return nil
}
