package cli

import (
	"testing"

	"github.com/sneakercreepers/creep/internal/calibrate"
	"github.com/sneakercreepers/creep/internal/discover"
	"github.com/sneakercreepers/creep/internal/exitcode"
	"github.com/sneakercreepers/creep/internal/planner"
	"github.com/sneakercreepers/creep/internal/repofile"
	"github.com/sneakercreepers/creep/internal/report"
)

// With pendingKinds empty since #212, no real kind reaches the unmapped
// path; a kind discover may add later must still be held out of the
// planner input and returned for the report, while a NoSQL sink is planned.
func TestPlannerInputHoldsOutUnmappedKinds(t *testing.T) {
	res := discover.Result{
		Routes: []discover.Route{{ID: 1, Methods: discover.AllMethods}},
		Sinks: []discover.Sink{
			{ID: 1, Route: 1, Kind: discover.SinkNoSQL, DynamicArg: true},
			{ID: 2, Route: 1, Kind: discover.SinkKind(200), DynamicArg: true},
		},
	}
	in, unmapped := plannerInput(res, planner.TierM, planner.Budget{Tokens: 10, StepTokens: 1})
	if len(unmapped) != 1 || unmapped[0] != 2 {
		t.Fatalf("unmapped %v, want [2]", unmapped)
	}
	if len(in.Sinks) != 1 || in.Sinks[0].Kind != planner.SinkNoSQL {
		t.Fatalf("planner sinks %+v, want the NoSQL sink only", in.Sinks)
	}
	plan, err := planner.Build(in)
	if err != nil || len(plan.Hypotheses) != 1 || plan.Hypotheses[0].Class != planner.ClassNoSQLInjection {
		t.Fatalf("plan %+v, %v", plan, err)
	}
}

// A sink of an unmapped kind stays not evaluated with reason unmapped_kind
// through planSinks, and that alone makes the run incomplete (exit 4).
func TestUnmappedKindMakesRunIncomplete(t *testing.T) {
	rs := repoScan{
		res: discover.Result{
			Routes: []discover.Route{{ID: 1, Methods: discover.AllMethods}},
			Sinks:  []discover.Sink{{ID: 1, Route: 1, Line: 3, Kind: discover.SinkKind(200), DynamicArg: true}},
		},
		paths: []string{"app.js"},
	}
	findings := baseFindings(rs)
	if _, err := planSinks(rs, planner.TierM, planner.Budget{Tokens: 10, StepTokens: 1}, findings, nil); err != nil {
		t.Fatal(err)
	}
	reason := incompleteReason("", findings, nil)
	if reason != reasonUnmappedKind || exitcode.ForReport(reason != "", false) != exitcode.Incomplete {
		t.Fatalf("reason %q, findings %+v", reason, findings)
	}
}

// Every discovery reason maps to the report reason of the same name (ADR
// 0017 D3: report JSON v1 gains nothing), and each is a gap, never by
// design. A reason discover adds fails here until it is mapped.
func TestDiscoveryReasonMappingIsExhaustive(t *testing.T) {
	for r := discover.Reason(1); r != 0; r++ {
		got, ok := skipReason(r)
		if r.String() == "" {
			if ok {
				t.Errorf("unnamed discover reason %d maps to %q", r, got)
			}
			continue
		}
		if !ok || string(got) != r.String() || got.ByDesign() {
			t.Errorf("discover reason %s maps to %q, %v", r, got, ok)
		}
		if _, err := report.New(report.Input{NotEvaluated: []report.NotEvaluated{{Path: "a.go", Reason: got}}}); err != nil {
			t.Errorf("report v1 refuses %s: %v", got, err)
		}
	}
}

// D2: only a file read in full (or not source) may count as complete. A
// file at the tripwire's cap, a missed canary, a cap in the reply and an
// unknown coverage are all gaps; a generated or minified mark is believed
// only for a file read in full with no candidate.
func TestDiscoveryGaps(t *testing.T) {
	full := discover.File{Coverage: discover.CoverageReadFull}
	tests := []struct {
		name    string
		file    discover.File
		mark    repofile.Ignored
		touched bool
		want    report.SkipReason
	}{
		{"read in full", full, 0, false, ""},
		{"not source", discover.File{Coverage: discover.CoverageNotSource}, 0, false, ""},
		{"tripwire cap", discover.File{Coverage: discover.CoverageReadFull, TripwireCut: true}, 0, false, report.SkipTruncated},
		{"canary missed", discover.File{Coverage: discover.CoverageCanaryMissed, Reason: discover.ReasonParseFailed}, 0, false, report.SkipParseFailed},
		{"reply cap", discover.File{Coverage: discover.CoverageTruncated, Reason: discover.ReasonTruncated}, 0, false, report.SkipTruncated},
		{"budget", discover.File{Coverage: discover.CoverageSendFailed, Reason: discover.ReasonBudget}, 0, false, report.SkipBudget},
		{"unknown coverage", discover.File{Coverage: 99}, 0, false, report.SkipSendFailed},
		{"never decided", discover.File{}, 0, false, report.SkipSendFailed},
		{"generated, nothing found", full, repofile.IgnoredGenerated, false, report.SkipGenerated},
		{"minified, nothing found", full, repofile.IgnoredMinified, false, report.SkipMinified},
		{"vendor path, nothing found", full, repofile.IgnoredVendor, false, report.SkipVendor},
		{"vendor path with a candidate", full, repofile.IgnoredVendor, true, ""},
		{"generated with a candidate", full, repofile.IgnoredGenerated, true, ""},
		{"generated, not read in full", discover.File{Coverage: discover.CoverageNotRead, Reason: discover.ReasonTooLarge}, repofile.IgnoredGenerated, false, report.SkipTooLarge},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := discover.Result{Files: []discover.File{tt.file}}
			if tt.touched {
				res.Sinks = []discover.Sink{{ID: 1, Route: 1, File: 0, Line: 1, Kind: discover.SinkSQL}}
			}
			gaps := discoveryGaps(res, []string{"gen.js"}, map[string]repofile.Ignored{"gen.js": tt.mark})
			got := report.SkipReason("")
			if len(gaps) == 1 {
				got = gaps[0].Reason
			}
			if got != tt.want || len(gaps) > 1 {
				t.Fatalf("gaps %+v, want %q", gaps, tt.want)
			}
			if tt.want != "" && !tt.want.ByDesign() && incompleteReason("", nil, gaps) == "" {
				t.Error("the gap does not make the run incomplete")
			}
		})
	}
}

// Every calibrate tier maps to a discovery tier of the same name.
func TestDiscoverTierMapping(t *testing.T) {
	for _, tier := range []calibrate.Tier{calibrate.TierS, calibrate.TierM, calibrate.TierL} {
		got, err := discoverTier(tier)
		if err != nil || string(got) != string(tier) {
			t.Errorf("discover tier %s = %q, %v", tier, got, err)
		}
	}
	if _, err := discoverTier("XL"); err == nil {
		t.Error("unknown tier mapped")
	}
}

// The summary counts whole-file egress, the inventory and each failed
// batch with its cause, and report.New accepts it.
func TestDiscoverySummary(t *testing.T) {
	res := discover.Result{Files: []discover.File{
		{Language: 4, Coverage: discover.CoverageReadFull, Batch: 1},
		{Language: 4, Coverage: discover.CoverageCanaryMissed, Reason: discover.ReasonParseFailed, Batch: 2},
		{Language: 5, Coverage: discover.CoverageCanaryMissed, Reason: discover.ReasonParseFailed, Batch: 2},
		{Language: 1, Coverage: discover.CoverageSendFailed, Reason: discover.ReasonParseFailed, Batch: 3},
		{Manifest: 2, Coverage: discover.CoverageNotSource},
		{Language: 1, Coverage: discover.CoverageNotRead, Reason: discover.ReasonTooLarge},
	}}
	d := discoverySummary(res)
	if d.WholeFiles != 4 {
		t.Errorf("whole files %d, want 4", d.WholeFiles)
	}
	want := []report.BatchNote{{Batch: 2, Files: 2, Cause: report.CauseCanaryMissed}, {Batch: 3, Files: 1, Cause: report.CauseInvalidReply}}
	if len(d.Batches) != 2 || d.Batches[0] != want[0] || d.Batches[1] != want[1] {
		t.Errorf("batches %+v, want %+v", d.Batches, want)
	}
	if len(d.Inventory) != 4 || d.Inventory[0].ID != "go" || d.Inventory[0].Files != 2 || d.Inventory[3].Kind != report.InventoryManifest {
		t.Errorf("inventory %+v", d.Inventory)
	}
	if _, err := report.New(report.Input{Discovery: d}); err != nil {
		t.Errorf("report refuses the summary: %v", err)
	}
}
