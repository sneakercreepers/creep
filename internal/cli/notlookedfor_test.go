package cli

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/sneakercreepers/creep/internal/baseline"
	"github.com/sneakercreepers/creep/internal/calibrate"
	"github.com/sneakercreepers/creep/internal/exitcode"
	"github.com/sneakercreepers/creep/internal/report"
)

var cScanGolden = filepath.Join("testdata", "scan_c.golden")

// cSource overflows a stack buffer with its argument: a memory-safety bug
// creep has no class for (#365). It holds no tripwire sink, so the run is
// complete and clean, which is the case that read as "covered" before.
const cSource = "#include <string.h>\n\nint main(int argc, char **argv) {\n\tchar buf[8];\n\tstrcpy(buf, argv[1]);\n\treturn 0;\n}\n"

// Acceptance (#365): a scan of a C file says, in the text summary and in
// every report file, that memory-safety bugs are not looked for.
func TestScanOfCFileSaysMemorySafetyIsNotLookedFor(t *testing.T) {
	golden, err := filepath.Abs(cScanGolden)
	if err != nil {
		t.Fatal(err)
	}
	cfg := scanRepo(t, map[string]string{"src/copy.c": cSource}, "")
	code, out, errOut := runScanWith(fakeDeps(&fakeModel{}, calibrate.TierM), "scan", "--config", cfg)
	if code != exitcode.OK {
		t.Fatalf("exit %d, want %d\n%s\n%s", code, exitcode.OK, out, errOut)
	}
	checkGolden(t, golden, out, true)
	for _, name := range []string{"report.json", "report.md", "report.sarif"} {
		data, err := os.ReadFile(filepath.Join(".creep", name))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(data), "memory_safety") || !strings.Contains(string(data), "CWE-119") {
			t.Errorf("%s does not list memory_safety (CWE-119) as not looked for", name)
		}
	}
	rep, err := readLastReport()
	if err != nil || !slices.ContainsFunc(rep.Coverage.NotLookedFor, func(c report.NotLookedFor) bool { return c.Class == "memory_safety" }) {
		t.Errorf("JSON coverage.not_looked_for = %+v, %v; want memory_safety", rep.Coverage.NotLookedFor, err)
	}
}

// evalLine and pickleLine are the sinks of evalApp, at lines 8 and 12.
const (
	evalLine   = "    return str(eval(request.args[\"e\"]))"
	pickleLine = "    return str(pickle.loads(request.data))"
	evalApp    = "from flask import Flask, request\nimport pickle\n\napp = Flask(__name__)\n\n" +
		"@app.route(\"/calc\")\ndef calc():\n" + evalLine + "\n\n" +
		"@app.route(\"/load\")\ndef load():\n" + pickleLine + "\n"
)

// evalModel finds both sinks only when the reader is asked their own
// class; a hypothesis asked as command_injection gets invalid output, so a
// planner classOf that folds them back into command injection leaves the
// run incomplete instead of passing (#365 tester finding).
func evalModel() *fakeModel {
	return &fakeModel{verdict: map[string]string{
		"code_injection": "vulnerable", "insecure_deserialization": "vulnerable", "command_injection": "invalid",
	}}
}

// Acceptance (#365): code eval and deserialization sinks are their own
// classes from the tripwire through the planner and the reader to the
// report; before #365 the tripwire tagged both shell and the report
// labeled them command_injection.
func TestEvalAndDeserializationAreNotCommandInjection(t *testing.T) {
	cfg := scanRepo(t, map[string]string{"app.py": evalApp}, "")
	code, out, errOut := runScanWith(fakeDeps(evalModel(), calibrate.TierM), "scan", "--config", cfg)
	if code != exitcode.GateExceeded {
		t.Fatalf("exit %d, want %d\n%s\n%s", code, exitcode.GateExceeded, out, errOut)
	}
	rep, err := readLastReport()
	if err != nil {
		t.Fatal(err)
	}
	want := map[int]string{8: "code_injection", 12: "insecure_deserialization"}
	for _, f := range rep.Findings {
		if f.Class == "command_injection" {
			t.Errorf("finding %s at line %d is labeled command_injection", f.ID, f.Line)
		}
		if class, ok := want[f.Line]; ok && f.Class == class && f.Status == report.StatusProbable {
			delete(want, f.Line)
		}
	}
	if len(want) != 0 {
		t.Errorf("missing probable findings %v in %+v", want, rep.Findings)
	}
}

// #365 changed the class, and the fingerprint covers it (ADR 0022): a
// baseline entry recorded for an eval or pickle sink as command_injection
// no longer suppresses its finding, which shows up as new once.
func TestBaselineFromCommandInjectionDoesNotHideCodeInjection(t *testing.T) {
	cfg := scanRepo(t, map[string]string{"app.py": evalApp}, "")
	deps := baselineDeps(evalModel(), baselineToday)
	if code, _, errOut := runScanWith(deps, "scan", "--config", cfg, "--baseline", "b.json", "--baseline-write"); code != exitcode.GateExceeded {
		t.Fatalf("write exit %d: %s", code, errOut)
	}
	if code, out, _ := runScanWith(deps, "scan", "--config", cfg, "--baseline", "b.json"); code != exitcode.OK {
		t.Fatalf("scan with its own baseline exit %d, want %d: %s", code, exitcode.OK, out)
	}
	relabelBaseline(t, map[string]string{"code_injection": evalLine, "insecure_deserialization": pickleLine})
	code, out, errOut := runScanWith(deps, "scan", "--config", cfg, "--baseline", "b.json")
	if code != exitcode.GateExceeded || strings.Contains(out, "suppressed:") {
		t.Fatalf("scan with a command_injection baseline exit %d, want %d and nothing suppressed\n%s\n%s", code, exitcode.GateExceeded, out, errOut)
	}
}

// relabelBaseline rewrites each entry of b.json as a pre-#365 scan wrote it: class
// command_injection, fingerprint over that class and the same sink line.
func relabelBaseline(t *testing.T, lines map[string]string) {
	t.Helper()
	data, err := os.ReadFile("b.json")
	if err != nil {
		t.Fatal(err)
	}
	f, err := baseline.Parse(data, baselineToday)
	if err != nil || len(f.Entries) != len(lines) {
		t.Fatalf("baseline %+v, %v; want %d entries", f, err, len(lines))
	}
	for i, e := range f.Entries {
		anchor := baseline.SinkAnchor(lines[e.Class])
		if baseline.Fingerprint(e.Class, e.Path, anchor) != e.Fingerprint {
			t.Fatalf("entry %+v: fingerprint is not over its class and sink line", e)
		}
		f.Entries[i].Class = "command_injection"
		f.Entries[i].Fingerprint = baseline.Fingerprint("command_injection", e.Path, anchor)
	}
	out, err := f.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	// G703: a fixed name in the test's own t.TempDir() repository.
	if err := os.WriteFile("b.json", out, 0o600); err != nil { //nolint:gosec
		t.Fatal(err)
	}
}

// The not-looked-for list and coverage never disagree: a class coverage
// lists as never readable is in the list, and a readable one is not.
func TestNotLookedForAgreesWithCoverage(t *testing.T) {
	listed := map[string]bool{}
	for _, c := range report.NotLookedForClasses() {
		if listed[c.Class] {
			t.Errorf("%s is listed twice", c.Class)
		}
		listed[c.Class] = true
	}
	for _, c := range classCoverage(coverageInput{planned: true}) {
		if readClasses[c.Class] == listed[c.Class] {
			t.Errorf("class %s: readable %v, listed as not looked for %v", c.Class, readClasses[c.Class], listed[c.Class])
		}
	}
	for class := range readClasses {
		if report.ClassCWE(class) == "" {
			t.Errorf("readable class %s has no CWE", class)
		}
	}
}
