package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

const testFingerprint = "0123456789abcdef0123456789abcdef"

func suppressed(status Status, s *Suppression) Finding {
	return Finding{ID: "f1", Class: "sqli", Status: status, Path: "app/db.py", Line: 12, Fingerprint: testFingerprint, Suppression: s}
}

var acceptedRisk = &Suppression{Kind: SuppressAccepted, Expires: "2027-01-01", Reason: "internal tool"}

// New refuses a suppression a baseline could not have made: on a finding
// the gate does not count (never on not_evaluated), without a fingerprint,
// or with a kind, expiry or reason outside the closed forms; and counts
// that do not add up.
func TestSuppressionChecked(t *testing.T) {
	noFingerprint := suppressed(StatusProbable, acceptedRisk)
	noFingerprint.Fingerprint = ""
	tests := []struct {
		name     string
		finding  Finding
		baseline BaselineUse
		ok       bool
	}{
		{"accepted on probable", suppressed(StatusProbable, acceptedRisk), BaselineUse{On: true, Entries: 1}, true},
		{"baseline on verified", suppressed(StatusVerified, &Suppression{Kind: SuppressBaseline, Expires: "2027-01-01"}), BaselineUse{On: true, Entries: 1}, true},
		{"fingerprint without baseline", suppressed(StatusProbable, nil), BaselineUse{}, true},
		{"not evaluated", suppressed(StatusNotEvaluated, acceptedRisk), BaselineUse{On: true, Entries: 1}, false},
		{"discarded", suppressed(StatusDiscarded, acceptedRisk), BaselineUse{On: true, Entries: 1}, false},
		{"no fingerprint", noFingerprint, BaselineUse{On: true, Entries: 1}, false},
		{"bad fingerprint", Finding{ID: "f1", Class: "sqli", Status: StatusProbable, Path: "a.py", Fingerprint: "XYZ"}, BaselineUse{}, false},
		{"unknown kind", suppressed(StatusProbable, &Suppression{Kind: "forever", Expires: "2027-01-01", Reason: "r"}), BaselineUse{On: true, Entries: 1}, false},
		{"no expiry", suppressed(StatusProbable, &Suppression{Kind: SuppressAccepted, Reason: "r"}), BaselineUse{On: true, Entries: 1}, false},
		{"accepted without reason", suppressed(StatusProbable, &Suppression{Kind: SuppressAccepted, Expires: "2027-01-01"}), BaselineUse{On: true, Entries: 1}, false},
		{"control text in reason", suppressed(StatusProbable, &Suppression{Kind: SuppressAccepted, Expires: "2027-01-01", Reason: "ok\x1b[2K"}), BaselineUse{On: true, Entries: 1}, false},
		{"suppressed without a baseline", suppressed(StatusProbable, acceptedRisk), BaselineUse{}, false},
		{"counts do not add up", suppressed(StatusProbable, acceptedRisk), BaselineUse{On: true, Entries: 3, Expired: 1}, false},
		{"negative count", suppressed(StatusProbable, nil), BaselineUse{On: true, Entries: 0, Expired: -1, Unmatched: 1}, false},
		{"counts with the baseline off", suppressed(StatusProbable, nil), BaselineUse{Entries: 2, Unmatched: 2}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(Input{Findings: []Finding{tt.finding}, Baseline: tt.baseline})
			if tt.ok != (err == nil) || (err != nil && !errors.Is(err, ErrInvalid)) {
				t.Errorf("New error %v, want ok %v", err, tt.ok)
			}
		})
	}
}

// Every suppression is listed: JSON on the finding, Markdown in its own
// section with the reason escaped, SARIF as the result's suppressions with
// the fingerprint, and the baseline line in Markdown and SARIF. A hostile
// reason that slipped past the file check would still print inert.
func TestSuppressionInEveryFormat(t *testing.T) {
	r, err := New(Input{
		Findings: []Finding{
			suppressed(StatusProbable, acceptedRisk),
			{ID: "f2", Class: "ssrf", Status: StatusProbable, Path: "b.py", Line: 3, Fingerprint: strings.Repeat("a", 32)},
		},
		Baseline: BaselineUse{On: true, Entries: 3, Expired: 1, Unmatched: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	r.Findings[0].Suppression.Reason = "a | b `c` [x](http://evil)"
	out := render(t, r)
	line := "baseline: 1 finding suppressed (0 baseline, 1 accepted risk), still listed and not counted by the gate; " +
		"1 expired entry suppresses nothing; 1 live entry matched no finding of this run (not read as fixed)"
	checks := []struct {
		format string
		want   []string
	}{
		{"json", []string{`"fingerprint": "` + testFingerprint + `"`, `"suppression": {`, `"kind": "accepted"`, `"expires": "2027-01-01"`}},
		{"md", []string{"## Suppressed", line, "| `f1` | `sqli` | `app/db.py:12` | `accepted` | `2027-01-01` | ``a \\| b `c` [x](http://evil)`` |", "`suppressed: accepted until 2027-01-01`"}},
		{"sarif", []string{`"creepFingerprint/v1": "` + testFingerprint + `"`, `"kind": "external"`, `"status": "accepted"`,
			`"justification": "suppressed: accepted risk until 2027-01-01: a | b`, `"id": "creep/baseline"`, line}},
	}
	for _, c := range checks {
		for _, w := range c.want {
			if !bytes.Contains(out[c.format], []byte(w)) {
				t.Errorf("%s lacks %q:\n%s", c.format, w, out[c.format])
			}
		}
	}
	var sarif struct {
		Runs []struct {
			Results []struct {
				Suppressions []any `json:"suppressions"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(out["sarif"], &sarif); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, res := range sarif.Runs[0].Results {
		n += len(res.Suppressions)
	}
	if len(sarif.Runs[0].Results) != 2 || n != 1 {
		t.Errorf("SARIF has %d results with %d suppressions, want both results listed and one suppressed", len(sarif.Runs[0].Results), n)
	}
}

// Without a baseline nothing about one is printed.
func TestNoBaselineNoSection(t *testing.T) {
	r := newTestReport(t, sampleInput(t, false))
	for format, data := range render(t, r) {
		for _, w := range []string{"Suppressed", "creep/baseline", "suppression"} {
			if bytes.Contains(data, []byte(w)) {
				t.Errorf("%s mentions %q with no baseline", format, w)
			}
		}
	}
}

func TestValidReason(t *testing.T) {
	tests := []struct {
		in string
		ok bool
	}{
		{"internal admin tool, fixed in #12", true},
		{"ünïcödé ok", true},
		{"", false}, {"   ", false}, {"a\nb", false}, {"a\rb", false}, {"a\tb", false},
		{"a\u202eb", false}, {"a\u200bb", false}, {"a\x7fb", false}, {"a\u0085b", false}, {"\xff", false},
		{"ok FAKE: suppressed nothing", false}, {"a b", false}, {"a b", false}, {"ab", false},
		{strings.Repeat("x", MaxReasonBytes), true}, {strings.Repeat("x", MaxReasonBytes+1), false},
	}
	for _, tt := range tests {
		if ValidReason(tt.in) != tt.ok {
			t.Errorf("ValidReason(%q) = %v", tt.in, !tt.ok)
		}
	}
}

// A report with suppressions stays valid against both published schemas.
func TestSuppressionValidatesAgainstSchemas(t *testing.T) {
	r := newTestReport(t, Input{
		Findings: []Finding{suppressed(StatusVerified, acceptedRisk), {ID: "f2", Class: "ssrf", Status: StatusProbable, Path: "b.py", Fingerprint: strings.Repeat("b", 32)}},
		Baseline: BaselineUse{On: true, Entries: 2, Expired: 1},
	})
	out := render(t, r)
	assertValid(t, loadJSON(t, filepath.Join("..", "..", "docs", "schemas", "report-v1.json")), out["json"])
	assertValid(t, loadJSON(t, filepath.Join("testdata", "sarif-schema-2.1.0.json")), out["sarif"])
}

// ReadJSON reads a suppression back as strictly as New checks it.
func TestReadJSONChecksSuppression(t *testing.T) {
	r, err := New(Input{Findings: []Finding{suppressed(StatusProbable, acceptedRisk)}, Baseline: BaselineUse{On: true, Entries: 1}})
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err := WriteJSON(&b, r); err != nil {
		t.Fatal(err)
	}
	back, err := ReadJSON(bytes.NewReader(b.Bytes()))
	if err != nil || back.Findings[0].Suppression == nil || back.Findings[0].Fingerprint != testFingerprint {
		t.Fatalf("ReadJSON = %+v, %v", back, err)
	}
	planted := bytes.Replace(b.Bytes(), []byte(`"status": "probable"`), []byte(`"status": "not_evaluated"`), 1)
	if _, err := ReadJSON(bytes.NewReader(planted)); !errors.Is(err, ErrInvalid) {
		t.Errorf("a suppressed not_evaluated finding read back: %v", err)
	}
}
