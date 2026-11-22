package cli

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/sneakercreepers/creep/internal/calibrate"
	"github.com/sneakercreepers/creep/internal/config"
	"github.com/sneakercreepers/creep/internal/exitcode"
	"github.com/sneakercreepers/creep/internal/gateway"
	"github.com/sneakercreepers/creep/internal/report"
)

// unchangedMarker sits only in files a --changed list leaves out, so a
// payload holding it proves the scan sent an unchanged file.
const unchangedMarker = "UNCHANGED_MARKER_26"

// recordingDeps is fakeDeps keeping every payload the model receives.
func recordingDeps(m *fakeModel, payloads *[][]byte) scanDeps {
	deps := fakeDeps(m, calibrate.TierM)
	deps.connect = func(*config.Resolved, string, io.Writer) (modelLink, error) {
		send := func(ctx context.Context, c gateway.Call) (*gateway.Reply, error) {
			*payloads = append(*payloads, slices.Clone(c.Payload))
			return m.send(ctx, c)
		}
		return modelLink{send: send, close: func() error { return nil }}, nil
	}
	return deps
}

// changedListFile writes a --changed list outside the repository.
func changedListFile(t *testing.T, data string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "changed.txt")
	writeFile(t, path, data)
	return path
}

// findingSites is each finding's class, path and line: IDs are numbered
// per run, so a full and an incremental scan are compared by site.
func findingSites(t *testing.T, path string) []string {
	t.Helper()
	rep, err := readLastReport()
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, f := range rep.Findings {
		if path == "" || f.Path == path {
			out = append(out, f.Class+" "+f.Path+":"+strconv.Itoa(f.Line))
		}
	}
	slices.Sort(out)
	return out
}

// Acceptance (#26): a one-file diff on the testdata apps plans exactly the
// hypotheses of the changed file, the ones a full scan plans there, and
// sends nothing of the unchanged files; the run is complete, and every
// format marks it incremental and lists the unchanged files.
func TestScanChangedEvaluatesOnlyListedFiles(t *testing.T) {
	cfg := scanRepo(t, map[string]string{
		"app.py": "@flask", "web/app.js": "@express",
		"lib/jobs.py": "import os\n\n\ndef run(cmd):\n    os.system(cmd)  # " + unchangedMarker + "\n",
	}, "")
	if code, out, errOut := runScanWith(fakeDeps(&fakeModel{}, calibrate.TierM), "scan", "--config", cfg); code != exitcode.OK {
		t.Fatalf("full scan: exit %d\n%s\n%s", code, out, errOut)
	}
	want := findingSites(t, "web/app.js")
	if len(want) == 0 || len(findingSites(t, "")) == len(want) {
		t.Fatalf("the full scan must plan sinks in web/app.js and elsewhere: %v", findingSites(t, ""))
	}
	var payloads [][]byte
	list := changedListFile(t, "web/app.js\nremoved.py\n")
	code, out, errOut := runScanWith(recordingDeps(&fakeModel{}, &payloads), "scan", "--changed", list, "--config", cfg)
	if code != exitcode.OK {
		t.Fatalf("incremental scan: exit %d\n%s\n%s", code, out, errOut)
	}
	if got := findingSites(t, ""); !slices.Equal(got, want) {
		t.Errorf("incremental findings %v, want the full scan's in web/app.js %v", got, want)
	}
	for _, p := range payloads {
		if bytes.Contains(p, []byte(unchangedMarker)) || bytes.Contains(p, []byte("from flask import")) {
			t.Fatalf("an unchanged file reached the model:\n%s", p)
		}
	}
	for _, line := range []string{
		"incremental scan (--changed): 1 listed file scanned, 1 listed path is no file creep reads",
		"2 unchanged files not evaluated (reason unchanged)",
		"coverage excludes 2 files left out by design (unchanged 2), listed above",
		"app.py  unchanged", "lib/jobs.py  unchanged",
		"discovery sends up to 1 whole source files",
	} {
		if !strings.Contains(out+errOut, line) {
			t.Errorf("output lacks %q:\n%s\n%s", line, out, errOut)
		}
	}
	checkJSONReport(t, "")
	checkIncrementalReports(t, []string{"app.py", "lib/jobs.py"})
}

// checkIncrementalReports reads the last run's reports: JSON lists exactly
// unchanged as the unchanged files, Markdown and SARIF mark the run.
func checkIncrementalReports(t *testing.T, unchanged []string) {
	t.Helper()
	rep, err := readLastReport()
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, n := range rep.Coverage.NotEvaluated {
		if n.Reason == report.SkipUnchanged {
			got = append(got, n.Path)
		}
	}
	if !slices.Equal(got, unchanged) {
		t.Errorf("JSON unchanged files %v, want %v", got, unchanged)
	}
	for name, mark := range map[string]string{"report.md": "**Incremental scan.**", "report.sarif": `"creep/incremental"`} {
		data, err := os.ReadFile(filepath.Join(stateDir, name))
		if err != nil || !bytes.Contains(data, []byte(mark)) {
			t.Errorf("%s lacks %q (%v):\n%s", name, mark, err, data)
		}
	}
}

// Protection (#26, R22): the list is untrusted. An entry that is not a
// clean repository-relative path fails the scan with exit 2 before any
// model call or state; a clean entry under .git or .creep, a directory or
// a deleted file is never read, and nothing is sent for it.
func TestScanChangedHostileLists(t *testing.T) {
	tests := []struct {
		name, list string
		wantCode   int
		wantOut    string
	}{
		{"parent escape", "../outside.py\n", exitcode.ConfigError, "--changed entry 1"},
		{"absolute", "/etc/passwd\n", exitcode.ConfigError, "not a clean path"},
		{"drive letter", "C:/Windows/win.ini\n", exitcode.ConfigError, "not a clean path"},
		{"backslash", "lib\\jobs.py\n", exitcode.ConfigError, "not a clean path"},
		{"git-quoted", "\"lib/caf\\303\\251.py\"\n", exitcode.ConfigError, "git's -z"},
		{"never walked", ".git/evil.py\x00.creep/evil.py\x00lib\x00removed.py\x00", exitcode.OK,
			"0 listed files scanned, 4 listed paths are no file creep reads"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := scanRepo(t, map[string]string{
				"lib/jobs.py":    "import os\nos.system(x)  # " + unchangedMarker + "\n",
				".git/evil.py":   "os.system(x)  # " + unchangedMarker + "\n",
				".creep/evil.py": "os.system(x)  # " + unchangedMarker + "\n",
			}, "")
			m := &fakeModel{}
			var payloads [][]byte
			code, out, errOut := runScanWith(recordingDeps(m, &payloads), "scan", "--changed", changedListFile(t, tt.list), "--config", cfg)
			if code != tt.wantCode || !strings.Contains(out+errOut, tt.wantOut) {
				t.Fatalf("exit %d, want %d with %q\n%s\n%s", code, tt.wantCode, tt.wantOut, out, errOut)
			}
			for _, p := range payloads {
				if bytes.Contains(p, []byte(unchangedMarker)) {
					t.Fatalf("a file the list may not reach was sent:\n%s", p)
				}
			}
			if tt.wantCode == exitcode.ConfigError && (m.calls != 0 || fileExists(filepath.Join(stateDir, "report.json"))) {
				t.Fatalf("a refused list made %d model calls or wrote a report", m.calls)
			}
		})
	}
}

// Protection (#26, R8): a listed link is not followed; the walk lists it
// not_regular as in a full scan, so the run is incomplete (exit 4) and the
// link's target is never sent.
func TestScanChangedLinkIsNotFollowed(t *testing.T) {
	cfg := scanRepo(t, map[string]string{"app.py": "print(1)\n"}, "")
	target := filepath.Join(t.TempDir(), "secret.py")
	writeFile(t, target, "os.system(x)  # "+unchangedMarker+"\n")
	if err := os.Symlink(target, "linked.py"); err != nil {
		t.Skipf("no symlinks here: %v", err)
	}
	var payloads [][]byte
	code, out, errOut := runScanWith(recordingDeps(&fakeModel{}, &payloads), "scan", "--changed", changedListFile(t, "linked.py\n"), "--config", cfg)
	if code != exitcode.Incomplete || !strings.Contains(out, "linked.py  not_regular") {
		t.Fatalf("exit %d, want %d with linked.py not_regular\n%s\n%s", code, exitcode.Incomplete, out, errOut)
	}
	for _, p := range payloads {
		if bytes.Contains(p, []byte(unchangedMarker)) {
			t.Fatalf("the link's target was sent:\n%s", p)
		}
	}
}

// TestChangedFlagRules: --changed limits scan and estimate only, needs a
// readable file, and an estimate measures only the listed files.
func TestChangedFlagRules(t *testing.T) {
	cfg := scanRepo(t, map[string]string{"app.py": "@flask", "web/app.js": "@express"}, "")
	list := changedListFile(t, "web/app.js\n")
	tests := []struct {
		name     string
		args     []string
		wantCode int
		wantOut  string
	}{
		{"no --diff flag (out of the product)", []string{"scan", "--diff", "origin/main", "--config", cfg}, exitcode.ConfigError, "flag provided but not defined: -diff"},
		{"why refuses it", []string{"why", "sink-1", "--changed", list}, exitcode.ConfigError, "limits only scan and estimate, not why"},
		{"version refuses it", []string{"--changed", list, "version"}, exitcode.ConfigError, "not version"},
		{"empty value", []string{"scan", "--changed", "", "--config", cfg}, exitcode.ConfigError, "needs a file"},
		{"missing list", []string{"scan", "--changed", list + ".none", "--config", cfg}, exitcode.ConfigError, "does not exist"},
		{"estimate measures the listed file", []string{"estimate", "--changed", list, "--config", cfg}, exitcode.OK,
			"walk: 1 files, up to 1 source files go to discovery whole and redacted; 1 files listed without reading"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deps := noModelDeps
			if tt.args[0] == "estimate" {
				deps = offlineDeps(t, true)
			}
			code, out, errOut := runScanWith(deps, tt.args...)
			if code != tt.wantCode || !strings.Contains(out+errOut, tt.wantOut) {
				t.Fatalf("exit %d, want %d with %q\n%s\n%s", code, tt.wantCode, tt.wantOut, out, errOut)
			}
			if tt.wantCode == exitcode.OK && !strings.Contains(out, "incremental scan (--changed): 1 listed file scanned") {
				t.Errorf("estimate lacks the incremental mark:\n%s", out)
			}
		})
	}
}

func fileExists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}
