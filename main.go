// main.go — entry point: flags, LDAPS listener, graceful shutdown.
package main

import (
	"context"
	"crypto/tls"
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
	// We extract -hash ourselves to accept both `-hash` (password read on
	// stdin) and `-hash=<password>`.
	hashMode, hashValue, rest := extractHashFlag(os.Args[1:])

	fs := flag.NewFlagSet("ldap-mask", flag.ExitOnError)
	configPath := fs.String("config", "config.yaml", "path to the YAML configuration file")
	showVersion := fs.Bool("version", false, "print the version and exit")
	_ = fs.Parse(rest)

	// No positional argument is expected. Ignoring them silently is precisely
	// what caused hashing standard input instead of the supplied password: we
	// refuse explicitly rather than guess.
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected positional argument %q (options start with \"-\")", fs.Arg(0))
	}

	if *showVersion {
		fmt.Println("ldap-mask " + version)
		return nil
	}

	if hashMode {
		if hashValue != "" {
			fmt.Fprintln(os.Stderr,
				"warning: a password passed as an argument is visible in the process "+
					"list (ps) and in the shell history; prefer \"ldap-mask -hash\" "+
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

	return serve(*configPath)
}

// extractHashFlag removes -hash / --hash / -hash=VALUE / -hash VALUE from args
// and returns the hash mode, the optional value and the remaining arguments.
//
// The separate form "-hash <password>" is accepted. Without it, the password
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
			// flag: "-hash -config x.yaml" must keep reading the
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

// serve loads the configuration and serves until SIGINT/SIGTERM.
func serve(configPath string) error {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := Load(configPath)
	if err != nil {
		return err
	}

	proxy, err := New(cfg, logger)
	if err != nil {
		return err
	}

	ln, err := listenFor(cfg)
	if err != nil {
		return err
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
