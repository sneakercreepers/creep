package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/sneakercreepers/creep/internal/calibrate"
	"github.com/sneakercreepers/creep/internal/discover"
	"github.com/sneakercreepers/creep/internal/exitcode"
	"github.com/sneakercreepers/creep/internal/planner"
	"github.com/sneakercreepers/creep/internal/report"
)

const flaskRoute = "from flask import Flask, request\nimport os\napp = Flask(__name__)\n\n@app.route(\"/x\")\ndef x():\n    return str(os.system(request.args[\"c\"]))\n"

// walkDir writes files under a temporary directory and walks it.
func walkDir(t *testing.T, files map[string]string) repoFiles {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil { //nolint:gosec // G703: names from the test table
			t.Fatal(err)
		}
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	got, err := walkRepo(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// The walk hands every regular file to discovery, in lexical order, so its
// bytes decide what is read in any language (ADR 0017, #366): nothing is
// unsupported_language any more, and sources() counts every file but a
// text format.
func TestWalkSendsEveryRegularFile(t *testing.T) {
	got := walkDir(t, map[string]string{
		"main.go": "package main\n", "app.php": "<?php\n", "App.java": "class A {}\n", "app.rb": "x = 1\n",
		"README.md": "# x\n", "go.mod": "module x\n", "bin/tool": "#!/usr/bin/env python3\n",
	})
	want := []string{"App.java", "README.md", "app.php", "app.rb", "bin/tool", "go.mod", "main.go"}
	if !slices.Equal(got.paths, want) || len(got.gaps) != 0 {
		t.Fatalf("paths %v gaps %+v, want %v and no gap", got.paths, got.gaps, want)
	}
	if n := got.sources(); n != 6 {
		t.Errorf("sources() = %d, want 6 (all but README.md)", n)
	}
}

// A name report.New would refuse on a finding (#177) is listed, never sent
// and never fatal: invalid_path, or not_code when discovery would never
// open it (#366). Windows cannot hold these names, so entryGap is called
// directly.
func TestEntryGapRefusedNames(t *testing.T) {
	proofs := openProofs(t, t.TempDir())
	tests := []struct {
		name string
		want report.SkipReason
		send bool
	}{
		{"app.py", "", true},
		{"a:b.py", report.SkipInvalidPath, false},
		{`web\app.go`, report.SkipInvalidPath, false},
		{"./app.py", report.SkipInvalidPath, false},
		{`web\notes.png`, report.SkipInvalidPath, false},
		{`web\notes.md`, report.SkipNotCode, false},
	}
	for _, tt := range tests {
		got, send := entryGap(tt.name, proofs)
		if got != tt.want || send != tt.send {
			t.Errorf("entryGap(%q) = %q, %v; want %q, %v", tt.name, got, send, tt.want, tt.send)
		}
	}
}

// Through the CLI on a file system that allows the names: a:b.py and
// web\app.py (#177) are listed, the run is incomplete (exit 4) and the rest
// of the repository is scanned.
func TestScanListsRefusedName(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("a:b.py names an alternate data stream on Windows; TestEntryGapRefusedNames covers the name")
	}
	cfg := scanRepo(t, map[string]string{"app.py": "@flask", "a:b.py": flaskRoute, `web\app.py`: flaskRoute}, "")
	code, out, _ := runScanWith(fakeDeps(&fakeModel{}, calibrate.TierM), "scan", "--config", cfg)
	if code != exitcode.Incomplete || !strings.Contains(out, "a:b.py  invalid_path") || !strings.Contains(out, "reason invalid_path") {
		t.Fatalf("exit %d\n%s", code, out)
	}
}

// Links and special files named as source are listed, not followed: a
// link could point outside the repository. A link the root resolves to a
// file with any other name is not (TestWalkListsDirectoryLinks).
func TestWalkListsLinks(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "real.go"), []byte("package x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "real.go"), filepath.Join(dir, "link.go")); err != nil {
		t.Skipf("no symlinks here: %v", err)
	}
	if err := os.Symlink("real.go", filepath.Join(dir, "notes.txt")); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	got, err := walkRepo(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	want := report.NotEvaluated{Path: "link.go", Reason: report.SkipNotRegular}
	if len(got.gaps) != 1 || got.gaps[0] != want || !slices.Equal(got.paths, []string{"real.go"}) {
		t.Fatalf("gaps %+v paths %v, want only %+v listed", got.gaps, got.paths, want)
	}
}

// Only the root's .git and .creep are skipped: a nested folder with either
// name is walked, so a repository cannot hide a route behind the name.
func TestWalkSkipsOnlyRootStateDirs(t *testing.T) {
	got := walkDir(t, map[string]string{
		".creep/x.py": flaskRoute, ".git/hooks/x.py": flaskRoute, "pkg/.creep/routes.py": flaskRoute, "pkg/.git/routes.py": flaskRoute,
	})
	want := []string{"pkg/.creep/routes.py", "pkg/.git/routes.py"}
	if !slices.Equal(got.paths, want) {
		t.Fatalf("walked %v, want %v", got.paths, want)
	}
}

// Acceptance (#175, #199 audit): planner.ErrInput (here a sink naming an
// unknown route; in the wild a result over 2^20 routes) fails the scan
// closed: every sink is not evaluated, no class is covered and the exit
// code is 4, never a clean result.
func TestPlannerRejectionFailsClosed(t *testing.T) {
	rs := repoScan{
		res: discover.Result{
			Files:  []discover.File{{ID: 0, Language: 1, Coverage: discover.CoverageReadFull}},
			Routes: []discover.Route{{ID: 1, File: 0, Methods: discover.AllMethods}},
			Sinks:  []discover.Sink{{ID: 1, Route: 7, File: 0, Line: 2, Kind: discover.SinkShell, DynamicArg: true}},
		},
		paths: []string{"app.py"},
	}
	findings := baseFindings(rs)
	_, err := planSinks(rs, planner.TierM, planner.Budget{Tokens: 1 << 20, StepTokens: 1}, findings, nil)
	if !errors.Is(err, planner.ErrInput) {
		t.Fatalf("planSinks err = %v, want planner.ErrInput", err)
	}
	res := rejectedScan(findings, nil)
	reason := incompleteReason(res.stop, res.findings, res.gaps)
	classes := classCoverage(coverageInput{findings: res.findings, gapped: true, planned: res.planned})
	if reason != reasonPlannerRejected || res.findings[0].Reason != reasonPlannerRejected {
		t.Fatalf("reason %q, finding %+v", reason, res.findings[0])
	}
	for _, c := range classes {
		if c.Status != report.ClassNotEvaluated {
			t.Errorf("class %s is %s after a planner rejection", c.Class, c.Status)
		}
	}
	if exitcode.ForReport(reason != "", false) != exitcode.Incomplete {
		t.Fatal("planner rejection does not exit 4")
	}
}
