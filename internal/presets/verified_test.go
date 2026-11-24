package presets

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"testing"
)

// verifiedPins holds commandDigest of each preset a maintainer checked with
// the real CLI (CONTRIBUTING.md, Manual canary check). The PR that sets
// verified: true adds the pin; a later change to program or args fails
// TestVerifiedPresetsArePinned until it sets verified: false again (#229).
var verifiedPins = map[string]string{
	"claude-code": "448088925e425c2b5a60c20cb1d05cda76a847b43bf4e2d6aca8e948c0405e5d",
	"gemini":      "d2f9cb5f5eaca0a7e487b1e1df2c2a0d808bca2dd847c5c3a42632ca44e7f6dc",
}

// commandDigest hashes the program and its arguments, each length-prefixed
// so moving text between arguments ("a b" vs "a", "b") changes the digest,
// and the verified_env names the manual check set (v0.4 review), so
// dropping one fails the pin as an argument change would. A preset without
// verified_env keeps the digest it had before the field existed.
func commandDigest(p Preset) string {
	h := sha256.New()
	for _, s := range append([]string{p.Program}, p.Args...) {
		fmt.Fprintf(h, "%d:%s\n", len(s), s)
	}
	if len(p.VerifiedEnv) > 0 {
		fmt.Fprintf(h, "verified_env\n")
		for _, s := range p.VerifiedEnv {
			fmt.Fprintf(h, "%d:%s\n", len(s), s)
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

// checkVerifiedPin says why a preset's verified flag and its pin disagree.
func checkVerifiedPin(p Preset, pins map[string]string) error {
	pin, pinned := pins[p.Name]
	switch {
	case p.IsVerified() && !pinned:
		return fmt.Errorf("preset %q is verified but has no pin: add %s to verifiedPins in the PR that records the manual check", p.Name, commandDigest(p))
	case p.IsVerified() && pin != commandDigest(p):
		return fmt.Errorf("preset %q: program, args or verified_env changed since the manual check: set verified: false until it passes again", p.Name)
	case !p.IsVerified() && pinned:
		return fmt.Errorf("preset %q is not verified: remove its stale pin", p.Name)
	}
	return nil
}

// Protection (#229 A4): a verified preset's command cannot change without
// resetting verified, so the warning for unverified flags cannot be skipped
// by an edit that reviewers miss.
func TestVerifiedPresetsArePinned(t *testing.T) {
	for _, name := range Names() {
		p, err := Lookup(name)
		if err != nil {
			t.Fatal(err)
		}
		if err := checkVerifiedPin(p, verifiedPins); err != nil {
			t.Error(err)
		}
	}
}

// The pin check itself catches every kind of edit to a verified preset.
func TestVerifiedPinCatchesEdits(t *testing.T) {
	base, err := Lookup("claude-code")
	if err != nil {
		t.Fatal(err)
	}
	pins := map[string]string{"claude-code": commandDigest(base)}
	yes, no := true, false
	edit := func(f func(*Preset)) Preset {
		p := base
		p.Args = slices.Clone(base.Args)
		f(&p)
		return p
	}
	tests := []struct {
		name string
		p    Preset
		pins map[string]string
		want string
	}{
		{"unchanged", base, pins, ""},
		{"arg added", edit(func(p *Preset) { p.Args = append(p.Args, "--dangerously-skip-permissions") }), pins, "changed"},
		{"arg removed", edit(func(p *Preset) {
			p.Args = slices.DeleteFunc(p.Args, func(a string) bool { return a == "--strict-mcp-config" })
		}), pins, "changed"},
		{"arg value changed", edit(func(p *Preset) { p.Args[2] = "Bash" }), pins, "changed"},
		{"args reordered", edit(func(p *Preset) { slices.Reverse(p.Args) }), pins, "changed"},
		{"text moved between args", edit(func(p *Preset) { p.Args = []string{"-p --tools", "", "--strict-mcp-config", "--output-format", "text"} }), pins, "changed"},
		{"program changed", edit(func(p *Preset) { p.Program = "claude-wrapper" }), pins, "changed"},
		{"reset to unverified", edit(func(p *Preset) { p.Verified = &no; p.Args = append(p.Args, "-x") }), map[string]string{}, ""},
		{"verified without pin", base, map[string]string{}, "no pin"},
		{"stale pin", edit(func(p *Preset) { p.Verified = &no }), pins, "stale pin"},
		{"verified with pin", edit(func(p *Preset) { p.Verified = &yes }), pins, ""},
	}
	for _, tt := range tests {
		err := checkVerifiedPin(tt.p, tt.pins)
		switch {
		case tt.want == "" && err != nil:
			t.Errorf("%s: %v", tt.name, err)
		case tt.want != "" && (err == nil || !strings.Contains(err.Error(), tt.want)):
			t.Errorf("%s: err = %v, want it to mention %q", tt.name, err, tt.want)
		}
	}
}

// The pin covers gemini's verified_env: dropping GEMINI_CLI_HOME from it,
// which would silence the "not verified for this run" warning, fails like
// an argument change (v0.4 review, auditor finding 3).
func TestVerifiedPinCoversVerifiedEnv(t *testing.T) {
	base, err := Lookup("gemini")
	if err != nil {
		t.Fatal(err)
	}
	pins := map[string]string{"gemini": commandDigest(base)}
	tests := []struct {
		name string
		env  []string
		want string
	}{
		{"unchanged", base.VerifiedEnv, ""},
		{"removed", nil, "verified_env changed"},
		{"replaced", []string{"GEMINI_OTHER"}, "verified_env changed"},
	}
	for _, tt := range tests {
		p := base
		p.VerifiedEnv = tt.env
		err := checkVerifiedPin(p, pins)
		if (tt.want == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), tt.want)) {
			t.Errorf("%s: err = %v, want %q", tt.name, err, tt.want)
		}
	}
	if !slices.Equal(base.VerifiedEnv, []string{"GEMINI_CLI_HOME"}) {
		t.Errorf("gemini verified_env = %q, want [GEMINI_CLI_HOME]", base.VerifiedEnv)
	}
}

// The exact argv of every preset. Each flag is load-bearing: gemini exits 55
// in its empty, untrusted working directory without --skip-trust; the other
// flags keep a tool path or the user's settings from turning tools back on.
// A change here is a preset change: comment the flag in the YAML file and,
// for a verified preset, reset verified.
func TestPresetArgsPinned(t *testing.T) {
	tests := map[string][]string{
		"claude-code": {"-p", "--tools", "", "--strict-mcp-config", "--output-format", "text"},
		"gemini":      {"--skip-trust", "--approval-mode", "default", "--extensions", "none", "--allowed-mcp-server-names", "creep-no-mcp-server", "--output-format", "text"},
		"codex":       {"exec", "--sandbox", "read-only", "--ignore-user-config", "-c", "features.shell_tool=false", "-c", "features.view_image=false", "-c", "features.apps=false", "-c", "features.plugins=false", "-c", "features.image_generation=false", "-c", "web_search=disabled", "-c", "project_root_markers=[]", "--skip-git-repo-check", "--ephemeral", "--color", "never", "-"},
		"ollama":      {"run", ModelPlaceholder, "--format", "json"},
	}
	for name, want := range tests {
		p, err := Lookup(name)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(p.Args, want) {
			t.Errorf("%s: args = %q, want %q", name, p.Args, want)
		}
	}
	if len(tests) != len(Names()) {
		t.Errorf("pinned %d presets, embedded %d: pin the new preset's args", len(tests), len(Names()))
	}
}
