package main

import (
	"bytes"
	"flag"
	"strings"
	"testing"
)

// TestExtractHashFlag covers the parsing of --hash, and in particular the
// separate form "--hash <password>".
//
// Non-regression: this form was previously ignored silently. The password
// passed as an argument was not seen, and the hash was computed on standard
// input — the user walked away with the hash of another password, with not the
// slightest signal, and their bind then failed with "invalid credentials".
func TestExtractHashFlag(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		wantMode  bool
		wantValue string
		wantRest  []string
	}{
		{
			name:     "no argument",
			args:     nil,
			wantMode: false,
		},
		{
			name:      "separate form",
			args:      []string{"--hash", "hunter2"},
			wantMode:  true,
			wantValue: "hunter2",
		},
		{
			name:      "attached form",
			args:      []string{"--hash=hunter2"},
			wantMode:  true,
			wantValue: "hunter2",
		},
		{
			name:      "single-dash separate form",
			args:      []string{"-hash", "hunter2"},
			wantMode:  true,
			wantValue: "hunter2",
		},
		{
			name:      "single-dash attached form",
			args:      []string{"-hash=hunter2"},
			wantMode:  true,
			wantValue: "hunter2",
		},
		{
			name:     "alone, password read on stdin",
			args:     []string{"--hash"},
			wantMode: true,
		},
		{
			// "--hash" followed by a flag: we must NOT consume the
			// flag as a password, otherwise --config disappears.
			name:      "--hash followed by a flag",
			args:      []string{"--hash", "--config", "other.yaml"},
			wantMode:  true,
			wantValue: "",
			wantRest:  []string{"--config", "other.yaml"},
		},
		{
			name:      "--hash separate then --config",
			args:      []string{"--hash", "hunter2", "--config", "other.yaml"},
			wantMode:  true,
			wantValue: "hunter2",
			wantRest:  []string{"--config", "other.yaml"},
		},
		{
			name:     "outside hash mode",
			args:     []string{"--config", "x.yaml"},
			wantMode: false,
			wantRest: []string{"--config", "x.yaml"},
		},
		{
			// The password itself can contain an "=".
			name:      "password containing an equals sign",
			args:      []string{"--hash=a=b=c"},
			wantMode:  true,
			wantValue: "a=b=c",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mode, value, rest := extractHashFlag(tc.args)
			if mode != tc.wantMode {
				t.Errorf("hashMode = %v, want %v", mode, tc.wantMode)
			}
			if value != tc.wantValue {
				t.Errorf("hashValue = %q, want %q", value, tc.wantValue)
			}
			if len(rest) != len(tc.wantRest) {
				t.Fatalf("rest = %q, want %q", rest, tc.wantRest)
			}
			for i := range rest {
				if rest[i] != tc.wantRest[i] {
					t.Fatalf("rest = %q, want %q", rest, tc.wantRest)
				}
			}
		})
	}
}

// TestUsageDoubleDash: the help spells every option with "--", including
// --hash, which is not registered on the FlagSet.
func TestUsageDoubleDash(t *testing.T) {
	fs := flag.NewFlagSet("ldap-mask", flag.ContinueOnError)
	registerFlags(fs)
	var buf bytes.Buffer
	fs.SetOutput(&buf)
	printUsage(fs)
	out := buf.String()
	for _, want := range []string{"\n  --config string\n", "\n  --map JSON\n", "\n  --hash [PASSWORD]\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("usage lacks %q:\n%s", want, out)
		}
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "  -") && !strings.HasPrefix(line, "  --") {
			t.Errorf("single-dash option in usage: %q", line)
		}
	}
}
