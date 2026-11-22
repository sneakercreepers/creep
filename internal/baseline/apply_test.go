package baseline

import (
	"errors"
	"strings"
	"testing"

	"github.com/sneakercreepers/creep/internal/report"
)

func finding(id string, status report.Status) report.Finding {
	return report.Finding{ID: id, Class: "sqli", Status: status, Path: "app/db.py", Line: 12, Fingerprint: fp}
}

func accepted(expires string) Entry {
	return Entry{Kind: report.SuppressAccepted, Fingerprint: fp, Class: "sqli", Path: "app/db.py", Expires: expires, Reason: "internal tool"}
}

func baselined(expires string) Entry {
	return Entry{Kind: report.SuppressBaseline, Fingerprint: fp, Class: "sqli", Path: "app/db.py", Expires: expires}
}

func with(e Entry, edit func(*Entry)) Entry {
	edit(&e)
	return e
}

// An entry suppresses one probable or verified finding with its exact
// fingerprint, class and path, until the day it expires; nothing else.
func TestBaselineSuppressesOnlyExactLiveMatch(t *testing.T) {
	noFingerprint := finding("f1", report.StatusProbable)
	noFingerprint.Fingerprint = ""
	tests := []struct {
		name           string
		findings       []report.Finding
		entries        []Entry
		wantSuppressed []bool
		want           report.BaselineUse
	}{
		{"probable matched", []report.Finding{finding("f1", report.StatusProbable)}, []Entry{accepted("2027-01-01")},
			[]bool{true}, report.BaselineUse{On: true, Entries: 1}},
		{"verified matched", []report.Finding{finding("f1", report.StatusVerified)}, []Entry{baselined("2027-01-01")},
			[]bool{true}, report.BaselineUse{On: true, Entries: 1}},
		{"not evaluated never", []report.Finding{finding("f1", report.StatusNotEvaluated)}, []Entry{accepted("2027-01-01")},
			[]bool{false}, report.BaselineUse{On: true, Entries: 1, Unmatched: 1}},
		{"discarded never", []report.Finding{finding("f1", report.StatusDiscarded)}, []Entry{accepted("2027-01-01")},
			[]bool{false}, report.BaselineUse{On: true, Entries: 1, Unmatched: 1}},
		{"no fingerprint never", []report.Finding{noFingerprint}, []Entry{with(accepted("2027-01-01"), func(e *Entry) { e.Fingerprint = "" })},
			[]bool{false}, report.BaselineUse{On: true, Entries: 1, Unmatched: 1}},
		{"expires today: suppresses nothing", []report.Finding{finding("f1", report.StatusProbable)}, []Entry{accepted("2026-11-21")},
			[]bool{false}, report.BaselineUse{On: true, Entries: 1, Expired: 1}},
		{"past expiry", []report.Finding{finding("f1", report.StatusProbable)}, []Entry{baselined("2020-01-01")},
			[]bool{false}, report.BaselineUse{On: true, Entries: 1, Expired: 1}},
		{"expires tomorrow: still live", []report.Finding{finding("f1", report.StatusProbable)}, []Entry{accepted("2026-11-22")},
			[]bool{true}, report.BaselineUse{On: true, Entries: 1}},
		{"other class", []report.Finding{finding("f1", report.StatusProbable)}, []Entry{with(accepted("2027-01-01"), func(e *Entry) { e.Class = "ssrf" })},
			[]bool{false}, report.BaselineUse{On: true, Entries: 1, Unmatched: 1}},
		{"glob-like path matches no other file", []report.Finding{finding("f1", report.StatusProbable)}, []Entry{with(accepted("2027-01-01"), func(e *Entry) { e.Path = "*" })},
			[]bool{false}, report.BaselineUse{On: true, Entries: 1, Unmatched: 1}},
		{"other fingerprint", []report.Finding{finding("f1", report.StatusProbable)}, []Entry{with(accepted("2027-01-01"), func(e *Entry) { e.Fingerprint = strings.Repeat("0", 32) })},
			[]bool{false}, report.BaselineUse{On: true, Entries: 1, Unmatched: 1}},
		// A copy of a baselined sink is a new finding: one entry, one finding.
		{"one entry for two identical sinks", []report.Finding{finding("f1", report.StatusProbable), finding("f2", report.StatusProbable)},
			[]Entry{accepted("2027-01-01")}, []bool{true, false}, report.BaselineUse{On: true, Entries: 1}},
		{"two entries for two identical sinks", []report.Finding{finding("f1", report.StatusProbable), finding("f2", report.StatusProbable)},
			[]Entry{accepted("2027-01-01"), baselined("2027-01-01")}, []bool{true, true}, report.BaselineUse{On: true, Entries: 2}},
		{"expired and live for one sink", []report.Finding{finding("f1", report.StatusProbable)},
			[]Entry{accepted("2020-01-01"), baselined("2027-01-01")}, []bool{true}, report.BaselineUse{On: true, Entries: 2, Expired: 1}},
		{"empty file", []report.Finding{finding("f1", report.StatusProbable)}, nil, []bool{false}, report.BaselineUse{On: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			use := Apply(tt.findings, &File{Version: Version, Entries: tt.entries}, today)
			if use != tt.want {
				t.Errorf("use %+v, want %+v", use, tt.want)
			}
			for i, f := range tt.findings {
				if f.Suppressed() != tt.wantSuppressed[i] {
					t.Errorf("finding %s suppressed %v, want %v", f.ID, f.Suppressed(), tt.wantSuppressed[i])
				}
			}
			// What Apply produces, report.New accepts: the counts add up.
			if _, err := report.New(report.Input{Findings: tt.findings, Baseline: use}); err != nil {
				t.Errorf("report.New refuses Apply's result: %v", err)
			}
		})
	}
}

// The suppression carries the entry's kind, expiry and reason, and a
// second Apply replaces what the first set.
func TestApplyCopiesEntry(t *testing.T) {
	findings := []report.Finding{finding("f1", report.StatusProbable)}
	Apply(findings, &File{Version: Version, Entries: []Entry{accepted("2027-01-01")}}, today)
	if s := findings[0].Suppression; s == nil || s.Kind != report.SuppressAccepted || s.Expires != "2027-01-01" || s.Reason != "internal tool" {
		t.Fatalf("suppression %+v", s)
	}
	Apply(findings, &File{Version: Version}, today)
	if findings[0].Suppressed() {
		t.Error("a second Apply kept a suppression no entry gives")
	}
}

func TestBaselineWriteNeedsFullRun(t *testing.T) {
	tests := []struct {
		name string
		run  report.RunInfo
		gaps []report.NotEvaluated
		want string
	}{
		{"complete", report.RunInfo{}, nil, ""},
		{"by design only", report.RunInfo{}, []report.NotEvaluated{{Path: "node_modules/x/a.js", Reason: report.SkipVendor}, {Path: "a_pb2.py", Reason: report.SkipGenerated}, {Path: "a.min.js", Reason: report.SkipMinified}}, ""},
		{"incomplete", report.RunInfo{Incomplete: true, Reason: "budget"}, nil, "incomplete (budget)"},
		{"a file gap", report.RunInfo{}, []report.NotEvaluated{{Path: "big.py", Reason: report.SkipTooLarge}}, "1 files"},
		{"an incremental scan's unchanged file", report.RunInfo{}, []report.NotEvaluated{{Path: "a.py", Reason: report.SkipUnchanged}}, "1 files"},
		{"a reason Writable does not know", report.RunInfo{}, []report.NotEvaluated{{Path: "a.py", Reason: "new_reason"}}, "1 files"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Writable(&report.Report{Run: tt.run, Coverage: report.Coverage{NotEvaluated: tt.gaps}})
			if (tt.want == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), tt.want)) {
				t.Errorf("Writable = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestRefresh(t *testing.T) {
	findings := []report.Finding{
		finding("kept-accepted", report.StatusProbable),
		ofClass(finding("new", report.StatusVerified), "ssrf"),
		ofClass(finding("old-baseline", report.StatusProbable), "path_traversal"),
		ofClass(finding("not-evaluated", report.StatusNotEvaluated), "nosql_injection"),
		ofClass(finding("discarded", report.StatusDiscarded), "command_injection"),
	}
	old := &File{Version: Version, Entries: []Entry{
		accepted("2027-01-01"),
		with(accepted("2020-01-01"), func(e *Entry) { e.Class = "xss" }),             // expired: dropped
		with(baselined("2026-12-01"), func(e *Entry) { e.Class = "path_traversal" }), // rewritten
		with(baselined("2026-12-01"), func(e *Entry) { e.Class = "gone" }),           // no finding: dropped
	}}
	Apply(findings, old, today)
	out, err := Refresh(old, findings, today)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Entry{}
	for _, e := range out.Entries {
		got[string(e.Kind)+" "+e.Class] = e
	}
	want := map[string]string{
		"accepted sqli":           "2027-01-01",
		"baseline ssrf":           "2027-02-19",
		"baseline path_traversal": "2027-02-19",
	}
	if len(got) != len(want) || len(out.Entries) != len(want) {
		t.Fatalf("entries %+v, want %v", out.Entries, want)
	}
	for k, expires := range want {
		if got[k].Expires != expires {
			t.Errorf("%s expires %q, want %q", k, got[k].Expires, expires)
		}
	}
}

func ofClass(f report.Finding, class string) report.Finding {
	f.Class = class
	return f
}

func TestAccept(t *testing.T) {
	old := &File{Version: Version, Entries: []Entry{baselined("2027-01-01")}}
	tests := []struct {
		name    string
		f       report.Finding
		days    int
		reason  string
		wantErr string
	}{
		{"probable", finding("f1", report.StatusProbable), 90, "admin only", ""},
		{"not evaluated", finding("f1", report.StatusNotEvaluated), 90, "r", "only a probable or verified"},
		{"discarded", finding("f1", report.StatusDiscarded), 90, "r", "only a probable or verified"},
		{"no fingerprint", withoutFingerprint(finding("f1", report.StatusProbable)), 90, "r", "only a probable or verified"},
		{"no expiry", finding("f1", report.StatusProbable), 0, "r", "1 to 365 days"},
		{"too far", finding("f1", report.StatusProbable), 366, "r", "1 to 365 days"},
		{"no reason", finding("f1", report.StatusProbable), 90, "", "reason"},
		{"blank reason", finding("f1", report.StatusProbable), 90, " \t", "reason"},
		{"multi-line reason", finding("f1", report.StatusProbable), 90, "ok\nmore", "reason"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := Accept(old, tt.f, tt.days, tt.reason, today)
			if tt.wantErr != "" {
				if !errors.Is(err, ErrNotAcceptable) || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("Accept error %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			// The baseline entry for the finding is replaced, not doubled.
			if len(out.Entries) != 1 || out.Entries[0].Kind != report.SuppressAccepted || out.Entries[0].Expires != "2027-02-19" || out.Entries[0].Reason != tt.reason {
				t.Errorf("entries %+v", out.Entries)
			}
			if len(old.Entries) != 1 || old.Entries[0].Kind != report.SuppressBaseline {
				t.Error("Accept changed its input")
			}
		})
	}
}

func withoutFingerprint(f report.Finding) report.Finding {
	f.Fingerprint = ""
	return f
}

func TestParseDays(t *testing.T) {
	tests := []struct {
		in   string
		want int
		ok   bool
	}{
		{"90d", 90, true}, {"1d", 1, true}, {"365d", 365, true},
		{"366d", 0, false}, {"0d", 0, false}, {"090d", 0, false}, {"90", 0, false}, {"-1d", 0, false},
		{"9999d", 0, false}, {"90D", 0, false}, {"3m", 0, false}, {"", 0, false}, {"2027-01-01", 0, false},
	}
	for _, tt := range tests {
		got, err := ParseDays(tt.in)
		if got != tt.want || (err == nil) != tt.ok {
			t.Errorf("ParseDays(%q) = %d, %v", tt.in, got, err)
		}
	}
}
