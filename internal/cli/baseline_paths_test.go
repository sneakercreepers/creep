package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/sneakercreepers/creep/internal/baseline"
	"github.com/sneakercreepers/creep/internal/exitcode"
)

const emptyBaseline = `{"version": 1, "entries": []}`

// A directory link the repository plants above the baseline would move the
// read and the write out of the tree past the final-name checks: scan,
// --baseline-write and accept refuse it, and nothing reaches its target.
func TestBaselineDirLinkRefused(t *testing.T) {
	cfg := scanRepo(t, map[string]string{"app.py": "@flask"}, "")
	outside := t.TempDir()
	mustWrite(t, filepath.Join(outside, "b.json"), emptyBaseline)
	if err := os.Symlink(outside, "ci"); err != nil {
		t.Skipf("symlinks unsupported here: %v", err)
	}
	// accept needs a probable finding in the last scan's report; the link
	// itself makes that scan incomplete (#214), which does not matter here.
	runScanWith(baselineDeps(vulnerableSQL(), baselineToday), "scan", "--config", cfg)
	id := probableSQLi(t, lastReport(t))[0].ID
	m := vulnerableSQL()
	deps := baselineDeps(m, baselineToday)
	for _, args := range [][]string{
		{"scan", "--config", cfg, "--baseline", "ci/b.json"},
		{"scan", "--config", cfg, "--baseline", "ci/b.json", "--baseline-write"},
		{"accept", id, "--expires", "30d", "--reason", "r", "--baseline", "ci/b.json"},
	} {
		code, _, stderr := runScanWith(deps, args...)
		if code != exitcode.ConfigError || !strings.Contains(stderr, "a directory above the file is a link") {
			t.Errorf("%v: exit %d: %s", args, code, stderr)
		}
	}
	if m.calls != 0 {
		t.Errorf("%d model calls before the refusal", m.calls)
	}
	// The write checks again: the link may appear after the read.
	if err := writeBaselineFile("ci/b.json", &baseline.File{Version: baseline.Version}); err == nil {
		t.Error("writeBaselineFile wrote through a directory link")
	}
	entries, _ := os.ReadDir(outside)
	if data, _ := os.ReadFile(filepath.Join(outside, "b.json")); string(data) != emptyBaseline || len(entries) != 1 {
		t.Errorf("the link's target changed: %d files, %s", len(entries), data)
	}
}

// On Windows a UNC or device path is refused before any lookup: resolving
// one alone authenticates to the host over SMB, traffic outside the
// gateway (invariant 5). The device path here touches no network; it names
// no file, so a lookup before the check would report that instead.
func TestBaselineDevicePathRefused(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("UNC and device paths exist only on Windows")
	}
	cfg := scanRepo(t, map[string]string{"app.py": "@flask"}, "")
	path := `\??\` + filepath.Join(t.TempDir(), "missing", "b.json")
	code, _, stderr := runScanWith(baselineDeps(vulnerableSQL(), baselineToday), "scan", "--config", cfg, "--baseline", path)
	if code != exitcode.ConfigError || !strings.Contains(stderr, "UNC and device paths are not allowed") {
		t.Errorf("exit %d: %s", code, stderr)
	}
}

// An incremental scan leaves files out as unchanged (#26), so a baseline
// taken from it would drop their entries: --baseline-write refuses it,
// writes nothing and never exits 0.
func TestBaselineWriteRefusesIncremental(t *testing.T) {
	cfg := scanRepo(t, map[string]string{"app.py": "@flask", "other.py": "print('x')\n"}, "")
	mustWrite(t, "b.json", emptyBaseline)
	list := changedListFile(t, "app.py\n")
	code, _, stderr := runScanWith(baselineDeps(vulnerableSQL(), baselineToday),
		"scan", "--config", cfg, "--changed", list, "--baseline", "b.json", "--baseline-write")
	if code == exitcode.OK || !strings.Contains(stderr, "nothing written: the run did not evaluate") {
		t.Errorf("exit %d: %s", code, stderr)
	}
	if data, _ := os.ReadFile("b.json"); string(data) != emptyBaseline {
		t.Errorf("the baseline changed: %s", data)
	}
}
