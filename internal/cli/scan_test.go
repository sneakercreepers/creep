package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sneakercreepers/creep/internal/calibrate"
	"github.com/sneakercreepers/creep/internal/exitcode"
	"github.com/sneakercreepers/creep/internal/gateway"
	"github.com/sneakercreepers/creep/internal/redact"
	"github.com/sneakercreepers/creep/internal/report"
)

// manyShellRoutes is a Flask app with n unauthenticated routes, each with a
// shell sink on request input: decoys that push real sinks past a step cap.
func manyShellRoutes(n int) string {
	var b strings.Builder
	b.WriteString("import os\nfrom flask import Flask, request\n\napp = Flask(__name__)\n")
	for i := range n {
		fmt.Fprintf(&b, "\n@app.route(\"/r%d\")\ndef r%d():\n    return str(os.system(request.args[\"c\"]))\n", i, i)
	}
	return b.String()
}

// longHandler is a Flask route whose data flow to the sink is longer than
// the tier M slice budget, so the reader answers from a partial slice.
func longHandler() string {
	var b strings.Builder
	b.WriteString("import sqlite3\nfrom flask import Flask, request\n\napp = Flask(__name__)\n\n@app.route(\"/big\")\ndef big():\n    q = request.args[\"q\"]\n")
	for i := range 600 {
		fmt.Fprintf(&b, "    q = q.strip()  # step %03d of a long flow that reaches the sink\n", i)
	}
	b.WriteString("    return str(sqlite3.connect(\"x.db\").execute(\"SELECT \" + q).fetchall())\n")
	return b.String()
}

// Acceptance (#175): through the CLI, an incomplete scan (run_full,
// send_failed, budget, a planner skip, a gap) prints the incomplete mark and
// exits 4, also when the gate is exceeded; a complete scan exits 0 within the
// gate and 1 over it.
func TestScanExitCodes(t *testing.T) {
	flask := map[string]string{"app.py": "@flask"}
	vulnerableSQL := map[string]string{"sql_injection": "vulnerable"}
	tests := []struct {
		name       string
		files      map[string]string
		config     string
		tier       calibrate.Tier
		verdict    map[string]string
		fail       map[string]error
		wantCode   int
		wantReason string // the incomplete mark's reason; "" means complete
	}{
		{"complete within gate", flask, "", calibrate.TierM, nil, nil, exitcode.OK, ""},
		{"complete over gate", flask, "", calibrate.TierM, vulnerableSQL, nil, exitcode.GateExceeded, ""},
		{"gate off", flask, "gates:\n  pr: none\n", calibrate.TierM, vulnerableSQL, nil, exitcode.OK, ""},
		{"ssrf under a critical gate", flask, "", calibrate.TierM, map[string]string{"ssrf": "vulnerable"}, nil, exitcode.OK, ""},
		{"tier S skips low risk by design", flask, "", calibrate.TierS, nil, nil, exitcode.OK, ""},
		{"send failed over gate", flask, "", calibrate.TierM, vulnerableSQL,
			map[string]error{"ssrf": errors.New("connection reset")}, exitcode.Incomplete, "send_failed"},
		{"budget exhausted", flask, "", calibrate.TierM, nil,
			map[string]error{"ssrf": fmt.Errorf("send: %w", gateway.ErrBudgetExhausted)}, exitcode.Incomplete, "budget"},
		{"redaction run full over gate", flask, "", calibrate.TierM, vulnerableSQL,
			map[string]error{"path_traversal": fmt.Errorf("redact: %w", redact.ErrRunFull)}, exitcode.Incomplete, "run_full"},
		{"planner token budget", flask, "budget:\n  max_tokens: 10000\n", calibrate.TierM, nil, nil, exitcode.Incomplete, "budget"},
		{"step cap from decoys", map[string]string{"app.py": manyShellRoutes(33)}, "", calibrate.TierS, nil, nil, exitcode.Incomplete, "step_cap"},
		{"inconclusive answer", flask, "", calibrate.TierM, map[string]string{"ssrf": "inconclusive"}, nil, exitcode.Incomplete, "inconclusive"},
		{"invalid answer", flask, "", calibrate.TierM, map[string]string{"ssrf": "invalid"}, nil, exitcode.Incomplete, "invalid_output"},
		{"partial slice not vulnerable", map[string]string{"app.py": longHandler()}, "", calibrate.TierM, nil, nil, exitcode.Incomplete, "partial_slice"},
		{"unsupported language", map[string]string{"app.py": "@flask", "web/app.js": "x()\n"}, "", calibrate.TierM, nil, nil, exitcode.Incomplete, "unsupported_language"},
		{"syntax error", map[string]string{"app.py": "@flask", "broken.py": "def f(:\n"}, "", calibrate.TierM, nil, nil, exitcode.Incomplete, "syntax_error"},
		{"vendor listed by design", map[string]string{"app.py": "@flask", "vendor/lib.py": "import os\n"}, "", calibrate.TierM, nil, nil, exitcode.OK, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := scanRepo(t, tt.files, tt.config)
			m := &fakeModel{verdict: tt.verdict, fail: tt.fail}
			code, out, errOut := runScanWith(fakeDeps(m, tt.tier), "scan", "--config", cfg)
			if code != tt.wantCode {
				t.Fatalf("exit %d, want %d\nstdout:\n%s\nstderr:\n%s", code, tt.wantCode, out, errOut)
			}
			mark := "INCOMPLETE RUN (reason " + tt.wantReason + ")"
			if got := strings.Contains(out, "INCOMPLETE RUN"); got != (tt.wantReason != "") || (got && !strings.Contains(out, mark)) {
				t.Fatalf("want mark %q (none if complete) in:\n%s", mark, out)
			}
			checkJSONReport(t, tt.wantReason)
		})
	}
}

// checkJSONReport reads the written report: an incomplete run is marked in
// it, with no class covered.
func checkJSONReport(t *testing.T, wantReason string) {
	t.Helper()
	rep, err := readLastReport()
	if err != nil {
		t.Fatal(err)
	}
	if rep.Run.Incomplete != (wantReason != "") || rep.Run.Reason != wantReason {
		t.Fatalf("report run = %+v, want reason %q", rep.Run, wantReason)
	}
	for _, c := range rep.Coverage.Classes {
		if wantReason != "" && c.Status == report.ClassCovered {
			t.Errorf("class %s covered in an incomplete run", c.Class)
		}
	}
}

// Every not-evaluated file is listed with its reason, escaped in the
// terminal; a run with one never reads as clean.
func TestScanListsFilesEscaped(t *testing.T) {
	hostile := "bidi\u202egnp.py"
	cfg := scanRepo(t, map[string]string{"app.py": "@flask", hostile: "def f(:\n", "node_modules/x/index.js": "x()\n"}, "")
	code, out, _ := runScanWith(fakeDeps(&fakeModel{}, calibrate.TierM), "scan", "--config", cfg)
	if code != exitcode.Incomplete {
		t.Fatalf("exit %d, want 4\n%s", code, out)
	}
	for _, want := range []string{`bidi\u202egnp.py  syntax_error`, "node_modules/x/index.js  vendor", "files not evaluated in full: 2"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\u202e") {
		t.Errorf("raw bidi rune reached the terminal:\n%q", out)
	}
}

// Errors before a report exists keep their codes: config 2, consent 2,
// model 3. None writes a report.
func TestScanFailsBeforeReport(t *testing.T) {
	consent := &gateway.ConsentError{Endpoint: "https://models.example.invalid", Err: gateway.ErrNoConsent}
	tests := []struct {
		name     string
		args     []string
		calErr   error
		noModel  bool
		wantCode int
		wantErr  string
	}{
		{"no model configured", []string{"scan"}, nil, true, exitcode.ConfigError, "model.endpoint and model.name"},
		{"other directory", []string{"scan", "/etc"}, nil, false, exitcode.ConfigError, "current directory"},
		{"consent refused", []string{"scan"}, consent, false, exitcode.ConfigError, "consent"},
		{"model failure", []string{"scan"}, errors.New("model said 500"), false, exitcode.ModelOrSandbox, "model said 500"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := scanRepo(t, map[string]string{"app.py": "@flask"}, "")
			args := append(tt.args, "--config", cfg)
			if tt.noModel {
				args = tt.args
			}
			deps := fakeDeps(&fakeModel{}, calibrate.TierM)
			deps.calibrate = fixedCalibration(calibrate.TierM, tt.calErr)
			code, out, errOut := runScanWith(deps, args...)
			if code != tt.wantCode || !strings.Contains(errOut, tt.wantErr) {
				t.Fatalf("exit %d, stderr %q; want %d and %q (stdout %q)", code, errOut, tt.wantCode, tt.wantErr, out)
			}
			if _, err := os.Stat(filepath.Join(stateDir, "report.json")); !os.IsNotExist(err) {
				t.Fatalf("a report was written: %v", err)
			}
		})
	}
}

// #205 audit M1a: a source file static has no grammar for (Go, PHP, ...)
// is listed as unsupported_language and the run exits 4, never 0 with every
// class covered; findings from the files static can read are still reported.
// Vendor copies stay by design, and non-source files are not listed.
func TestScanListsUngrammaredSource(t *testing.T) {
	tests := []struct {
		name     string
		files    map[string]string
		wantCode int
		listed   []string
		findings int
	}{
		{"go only", map[string]string{"main.go": "package main\n", "internal/db/q.GO": "package db\n", "README.md": "# x\n"},
			exitcode.Incomplete, []string{"main.go  unsupported_language", "internal/db/q.GO  unsupported_language", "files not evaluated in full: 2"}, 0},
		{"flask plus php", map[string]string{"app.py": "@flask", "legacy/login.php": "<?php echo 1;\n"},
			exitcode.Incomplete, []string{"legacy/login.php  unsupported_language", "files not evaluated in full: 1"}, 4},
		{"vendored go by design", map[string]string{"app.py": "@flask", "vendor/x/y.go": "package y\n", "notes.txt": "x\n"},
			exitcode.OK, []string{"vendor/x/y.go  vendor", "files not evaluated in full: 1"}, 4},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := scanRepo(t, tt.files, "")
			code, out, errOut := runScanWith(fakeDeps(&fakeModel{}, calibrate.TierM), "scan", "--config", cfg)
			if code != tt.wantCode {
				t.Fatalf("exit %d, want %d\n%s\n%s", code, tt.wantCode, out, errOut)
			}
			for _, want := range tt.listed {
				if !strings.Contains(out, want) {
					t.Errorf("output lacks %q:\n%s", want, out)
				}
			}
			rep, err := readLastReport()
			if err != nil || len(rep.Findings) != tt.findings {
				t.Fatalf("report: %v, %d findings, want %d", err, len(rep.Findings), tt.findings)
			}
			wantReason := ""
			if tt.wantCode == exitcode.Incomplete {
				wantReason = string(report.SkipUnsupported)
			}
			checkJSONReport(t, wantReason)
		})
	}
}

// With --format json the report itself goes to stdout and the incomplete
// mark to stderr, so a redirected report never hides it.
func TestScanFormatJSONMarksStderr(t *testing.T) {
	cfg := scanRepo(t, map[string]string{"app.py": "@flask", "web/app.js": "x()\n"}, "")
	code, out, errOut := runScanWith(fakeDeps(&fakeModel{}, calibrate.TierM), "scan", "--format", "json", "--config", cfg)
	if code != exitcode.Incomplete || !strings.Contains(errOut, "INCOMPLETE RUN (reason unsupported_language)") {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	if _, err := report.ReadJSON(strings.NewReader(out)); err != nil {
		t.Fatalf("stdout is not a JSON report: %v\n%s", err, out)
	}
}
