package report

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// TestCheckVerification: the outcome holds only a known status and IDs, so
// no format prints text a repository or a runtime chose; a bad one fails
// New rather than being guessed.
func TestCheckVerification(t *testing.T) {
	tests := []struct {
		name string
		v    Verification
		ok   bool
	}{
		{"off", Verification{}, true},
		{"built", Verification{Status: VerificationAppBuilt}, true},
		{"unavailable", Verification{Status: VerificationUnavailable, Reason: "no_build_file"}, true},
		{"unavailable with detail", Verification{Status: VerificationUnavailable, Reason: "build_failed", Detail: "exit_1"}, true},
		{"unknown status", Verification{Status: "verified"}, false},
		{"off with reason", Verification{Reason: "no_runtime"}, false},
		{"built with reason", Verification{Status: VerificationAppBuilt, Reason: "build_failed"}, false},
		{"unavailable without reason", Verification{Status: VerificationUnavailable}, false},
		{"control bytes", Verification{Status: VerificationUnavailable, Reason: "x\x1b[2J"}, false},
		{"unknown reason", Verification{Status: VerificationUnavailable, Reason: "made_up"}, false},
		{"free-text detail", Verification{Status: VerificationUnavailable, Reason: "build_failed", Detail: "see `rm -rf`"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := sampleInput(t, false)
			in.Verification = tt.v
			_, err := New(in)
			if tt.ok != (err == nil) || err != nil && !errors.Is(err, ErrInvalid) {
				t.Errorf("New with %+v: %v", tt.v, err)
			}
		})
	}
}

// TestVerificationInEveryFormat: Markdown and SARIF state the outcome and
// its reason, JSON v1 stays byte for byte the same (ADR 0009), and a run
// with the sandbox off says nothing about it.
func TestVerificationInEveryFormat(t *testing.T) {
	base := render(t, newTestReport(t, sampleInput(t, false)))
	tests := []struct {
		v    Verification
		want string
	}{
		{Verification{Status: VerificationUnavailable, Reason: "dockerfile_refused", Detail: "add_url"}, "dockerfile_refused: add_url"},
		{Verification{Status: VerificationAppBuilt}, "built offline in the sandbox"},
	}
	for _, tt := range tests {
		in := sampleInput(t, false)
		in.Verification = tt.v
		got := render(t, newTestReport(t, in))
		for _, ext := range []string{"md", "sarif"} {
			if !strings.Contains(string(got[ext]), tt.want) || !strings.Contains(string(got[ext]), "probable") {
				t.Errorf("%s lacks %q:\n%s", ext, tt.want, got[ext])
			}
		}
		if !bytes.Equal(got["json"], base["json"]) {
			t.Errorf("the JSON report changed with verification %+v", tt.v)
		}
	}
	for ext, out := range base {
		if bytes.Contains(bytes.ToLower(out), []byte("verification")) {
			t.Errorf("%s mentions verification with the sandbox off:\n%s", ext, out)
		}
	}
}
