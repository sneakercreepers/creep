package cli

import (
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/sneakercreepers/creep/internal/exitcode"
	"github.com/sneakercreepers/creep/internal/gitindex/gitindextest"
	"github.com/sneakercreepers/creep/internal/report"
)

// plantedIndex is a .git/index an archive ships: it tracks only tracked,
// with stats when given, so every other ignored tree looks installed.
func plantedIndex(files map[string]string, tracked []string, stats map[string]gitindextest.Stat) map[string]string {
	out := map[string]string{gitIndexPath: string(gitindextest.Build(gitindextest.Spec{Version: 2, Paths: tracked, Stats: stats}))}
	for name, content := range files {
		out[name] = content
	}
	return out
}

// TestPlantedIndexNeverExitsZero (#380, #376 auditor M2): an archive that
// keeps one decoy file beside an index that disagrees with its tree and an
// ignore file marking the rest of its code vendor never exits 0: vendor
// proven by such an index that hides more code bytes than discovery reads
// stays unread but is listed vendor_exceeds_read, so the run is
// incomplete. An index that agrees with the tree, as git writes it, keeps
// a large install vendor with exit 0.
func TestPlantedIndexNeverExitsZero(t *testing.T) {
	decoy := map[string]string{"main.py": helloRoute, ".gitignore": "src/\n", "src/app.py": "@flask"}
	tracked := []string{".gitignore", "main.py"}
	far := gitindextest.Stat{Size: 1, MtimeSec: math.MaxUint32} // a size the disk does not hold, recorded after any edit
	exceeds := []string{"src/app.py  vendor_exceeds_read", "INCOMPLETE RUN (reason vendor_exceeds_read)"}
	install := map[string]string{"main.py": helloRoute, ".gitignore": "node_modules/\n", "node_modules/lib/big.js": strings.Repeat("module.exports = 1\n", 400)}
	runBydesignCases(t, []bydesignCase{
		{"one decoy file", plantedIndex(decoy, tracked, nil), exitcode.Incomplete, string(report.SkipVendorExceedsRead), exceeds},
		{"decoy beside several trees", plantedIndex(map[string]string{"main.py": helloRoute, ".gitignore": "/lib\napi/\n", "lib/a.js": "@express", "api/b.py": "@flask"}, tracked, nil),
			exitcode.Incomplete, string(report.SkipVendorExceedsRead), []string{"lib/a.js  vendor_exceeds_read", "api/b.py  vendor_exceeds_read"}},
		{"index size the disk does not hold", plantedIndex(decoy, tracked, map[string]gitindextest.Stat{"main.py": far, ".gitignore": {Size: 5, MtimeSec: recordedAt}}),
			exitcode.Incomplete, string(report.SkipVendorExceedsRead), exceeds},
		{"index mode git never writes", plantedIndex(decoy, tracked, map[string]gitindextest.Stat{
			"main.py": {Mode: 0o100600, Size: uint32(len(helloRoute)), MtimeSec: recordedAt}, ".gitignore": {Size: uint32(len("src/\n")), MtimeSec: recordedAt}}),
			exitcode.Incomplete, string(report.SkipVendorExceedsRead), exceeds},
		{"absent entries beside an exact decoy with a made-up mtime", plantedIndex(decoy, []string{"a.py", "b.py", "c.py", "main.py"}, map[string]gitindextest.Stat{
			"main.py": {Size: uint32(len(helloRoute)), MtimeSec: 1}, "a.py": {MtimeSec: 1}, "b.py": {MtimeSec: 1}, "c.py": {MtimeSec: 1}}),
			exitcode.Incomplete, string(report.SkipVendorExceedsRead), exceeds},
		{"absent entries beside an exact decoy", plantedIndex(decoy, []string{"a.py", "b.py", "c.py", "main.py"}, map[string]gitindextest.Stat{
			"main.py": {Size: uint32(len(helloRoute)), MtimeSec: recordedAt}, "a.py": {MtimeSec: recordedAt}, "b.py": {MtimeSec: recordedAt}, "c.py": {MtimeSec: recordedAt}}),
			exitcode.Incomplete, string(report.SkipVendorExceedsRead), exceeds},
		{"index tracking only missing files", plantedIndex(decoy, []string{"gone.py"}, nil), exitcode.Incomplete, string(report.SkipVendorExceedsRead), exceeds},
		{"decoy only a .gitignore beside", plantedIndex(map[string]string{".gitignore": "src/\n", "README.md": "# x\n", "src/app.py": "@flask"}, []string{".gitignore", "README.md"}, nil),
			exitcode.GateExceeded, "", []string{"probable  sqli  src/app.py:"}},
		{"index tracking a directory as a file", plantedIndex(decoy, []string{"src"}, nil), exitcode.GateExceeded, "", []string{"probable  sqli  src/app.py:"}},
		{"inconsistent index, large install", plantedIndex(install, tracked, nil), exitcode.Incomplete, string(report.SkipVendorExceedsRead),
			[]string{"node_modules/lib/big.js  vendor_exceeds_read"}},
		{"consistent index, large install", withGitIndex(install, []string{"node_modules"}), exitcode.OK, "",
			[]string{"node_modules/lib/big.js  vendor", "coverage excludes 1 file left out by design (vendor 1), listed above"}},
		{"inconsistent index, small install", plantedIndex(map[string]string{"main.py": helloRoute, ".gitignore": "deps/\n", "deps/x.py": "x = 1\n"}, tracked, nil), exitcode.OK, "",
			[]string{"deps/x.py  vendor"}},
	})
}

// TestRealIndexKeepsInstallVendor (#380 acceptance): an index git wrote
// keeps an installed tree far larger than the code vendor, unbounded. testdata/gitindex/install.index was
// written by git 2.49 (git add -A, core.autocrlf=false) over exactly the
// tracked files below, beside an ignored, untracked node_modules.
func TestRealIndexKeepsInstallVendor(t *testing.T) {
	index, err := os.ReadFile(filepath.Join("testdata", "gitindex", "install.index"))
	if err != nil {
		t.Fatal(err)
	}
	repo := t.TempDir()
	files := map[string]string{"main.py": helloRoute, ".gitignore": "node_modules/\n", "node_modules/lib/index.js": strings.Repeat("module.exports = 1\n", 400), gitIndexPath: string(index)}
	for name, content := range files {
		writeTreeFile(t, repo, name, content)
	}
	got := walkTree(t, repo)
	if !slices.Contains(got.gaps, report.NotEvaluated{Path: "node_modules/lib/index.js", Reason: report.SkipVendor}) || !slices.Contains(got.paths, "main.py") {
		t.Errorf("paths %v gaps %+v: want main.py read and the install vendor", got.paths, got.gaps)
	}
}

// TestVendorBound pins the rule: vendor may hide at most as many bytes of
// files discovery would open as it reads, .gitignore files not counted on
// either side and files it never opens (not_code) not counted at all.
func TestVendorBound(t *testing.T) {
	tests := []struct {
		name   string
		read   string // main.go
		hidden string // deps/x.go
		extra  map[string]string
		want   report.SkipReason
	}{
		{"equal bytes", "package a\n", "package b\n", nil, report.SkipVendor},
		{"one byte more", "package a\n", "package bb\n", nil, report.SkipVendorExceedsRead},
		{"far less", strings.Repeat("x", 4096), "package b\n", nil, report.SkipVendor},
		{"a large .gitignore does not count", "package a\n", "package bb\n", map[string]string{".gitignore": "deps/\n" + strings.Repeat("#\n", 4096)}, report.SkipVendorExceedsRead},
		{"text formats do not count", "package a\n", "package bb\n", map[string]string{"README.md": strings.Repeat("x", 4096)}, report.SkipVendorExceedsRead},
		{"vendor text formats do not count", "package a\n", "package b\n", map[string]string{"deps/README.md": strings.Repeat("x", 4096)}, report.SkipVendor},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := t.TempDir()
			files := map[string]string{".gitignore": "deps/\n", "main.go": tt.read, "deps/x.go": tt.hidden}
			for name, content := range tt.extra {
				files[name] = content
			}
			for name, content := range files {
				writeTreeFile(t, repo, name, content)
			}
			writeTreeFile(t, repo, gitIndexPath, string(gitindextest.Build(gitindextest.Spec{Version: 2, Paths: []string{".gitignore", "main.go"}})))
			got := walkTree(t, repo)
			if !slices.Contains(got.gaps, report.NotEvaluated{Path: "deps/x.go", Reason: tt.want}) {
				t.Errorf("gaps %+v: want deps/x.go %s", got.gaps, tt.want)
			}
			if tt.want == report.SkipVendorExceedsRead && report.SkipVendorExceedsRead.ByDesign() {
				t.Error("vendor_exceeds_read is by design: the run would pass")
			}
		})
	}
}
