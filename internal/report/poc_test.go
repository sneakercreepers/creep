package report

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// Protection (#25): a report never carries a verified finding from a PoC
// that verified in no run, and a rate goes only on a verified finding,
// within the runs a repetition can make.
func TestPoCRateChecked(t *testing.T) {
	tests := []struct {
		name   string
		status Status
		rate   PoCRate
		ok     bool
	}{
		{"none", StatusProbable, PoCRate{}, true},
		{"stable", StatusVerified, PoCRate{5, 5}, true},
		{"intermittent", StatusVerified, PoCRate{2, 5}, true},
		{"verified without a rate (JSON read back)", StatusVerified, PoCRate{}, true},
		{"0 of 5", StatusVerified, PoCRate{0, 5}, false},
		{"0 of 5 on probable", StatusProbable, PoCRate{0, 5}, false},
		{"rate on probable", StatusProbable, PoCRate{3, 5}, false},
		{"rate on discarded", StatusDiscarded, PoCRate{5, 5}, false},
		{"more verified than runs", StatusVerified, PoCRate{6, 5}, false},
		{"too many runs", StatusVerified, PoCRate{21, 21}, false},
		{"negative", StatusVerified, PoCRate{-1, 5}, false},
		{"verified with no runs", StatusVerified, PoCRate{1, 0}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := sampleInput(t, false)
			in.Findings[1].Status, in.Findings[1].PoC = tt.status, tt.rate
			_, err := New(in)
			if tt.ok != (err == nil) || err != nil && !errors.Is(err, ErrInvalid) {
				t.Errorf("%s %+v: %v", tt.status, tt.rate, err)
			}
		})
	}
}

// TestPoCRateInFormats: Markdown and SARIF show an intermittent finding's
// rate, the JSON report is byte for byte the same (v1 does not change),
// and a stable one reads verified in every run.
func TestPoCRateInFormats(t *testing.T) {
	base := render(t, newTestReport(t, sampleInput(t, false)))
	in := sampleInput(t, false)
	in.Findings[3].PoC = PoCRate{3, 5}
	in.Verification = Verification{Status: VerificationAppBuilt, PoCs: PoCSummary{Ran: 2, Intermittent: 1, NotRun: 1}}
	got := render(t, newTestReport(t, in))
	for ext, want := range map[string][]string{
		"md":    {"`verified in 3/5 runs, intermittent`", "PoCs ran for 2 findings: 0 verified in every run, 1 intermittent, 1 not reproduced; 1 got no PoC run"},
		"sarif": {`"poc_verified_runs": 3`, `"poc_runs": 5`, "(verified, verified in 3/5 runs, intermittent, stable discovery: seen in 3 of 3 runs)", "1 intermittent"},
	} {
		for _, w := range want {
			if !strings.Contains(string(got[ext]), w) {
				t.Errorf("%s lacks %q:\n%s", ext, w, got[ext])
			}
		}
	}
	if !bytes.Equal(got["json"], base["json"]) {
		t.Errorf("the JSON report changed with a PoC rate")
	}
	if text := (PoCRate{5, 5}).Text(); text != "verified in 5/5 runs" {
		t.Errorf("stable rate text %q", text)
	}
}

// TestPoCSummaryChecked: counts only on an app_built verification, none
// negative, and no more verified or intermittent PoCs than ran.
func TestPoCSummaryChecked(t *testing.T) {
	tests := []struct {
		name string
		v    Verification
		ok   bool
	}{
		{"built, PoCs", Verification{Status: VerificationAppBuilt, PoCs: PoCSummary{Ran: 3, Verified: 1, Intermittent: 1, NotRun: 2}}, true},
		{"built, none", Verification{Status: VerificationAppBuilt}, true},
		{"more verified than ran", Verification{Status: VerificationAppBuilt, PoCs: PoCSummary{Ran: 1, Verified: 1, Intermittent: 1}}, false},
		{"negative", Verification{Status: VerificationAppBuilt, PoCs: PoCSummary{NotRun: -1}}, false},
		{"unavailable with PoCs", Verification{Status: VerificationUnavailable, Reason: "no_port", PoCs: PoCSummary{Ran: 1}}, false},
		{"off with PoCs", Verification{PoCs: PoCSummary{NotRun: 1}}, false},
		{"no port", Verification{Status: VerificationUnavailable, Reason: "no_port"}, true},
		{"start failed", Verification{Status: VerificationUnavailable, Reason: "start_failed", Detail: "app"}, true},
	}
	for _, tt := range tests {
		in := sampleInput(t, false)
		in.Verification = tt.v
		if _, err := New(in); tt.ok != (err == nil) {
			t.Errorf("%s: %v", tt.name, err)
		}
	}
}
