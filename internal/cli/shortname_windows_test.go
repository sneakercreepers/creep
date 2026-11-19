package cli

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/sneakercreepers/creep/internal/calibrate"
	"github.com/sneakercreepers/creep/internal/exitcode"
)

// TestScanShortNameAlias (#267 tester H1): git for Windows checks
// node_m~1/app/app.js out into node_modules/app/ once node_modules/ exists,
// so the index tracks the tree under a name the scan never sees. Identity,
// not the name, decides: the committed app is evaluated. Skipped on a
// volume that makes no 8.3 names.
func TestScanShortNameAlias(t *testing.T) {
	cfg := scanRepo(t, map[string]string{
		"main.py": helloRoute, "node_modules/.keep": "", "node_modules/app/package.json": "{}", "node_modules/app/app.js": "@express",
	}, "")
	short := shortName(t, "node_modules")
	if short == "node_modules" {
		t.Skip("this volume makes no 8.3 names")
	}
	index := buildGitIndex(gitIndexSpec{version: 2, paths: []string{
		short + "/app/app.js", short + "/app/package.json", "main.py", "node_modules/.keep",
	}})
	writeTreeFile(t, ".", gitIndexPath, string(index))
	m := &fakeModel{verdict: map[string]string{"command_injection": "vulnerable"}}
	code, out, errOut := runScanWith(fakeDeps(m, calibrate.TierM), "scan", "--config", cfg)
	if code != exitcode.GateExceeded {
		t.Fatalf("exit %d with the tree tracked as %s, want %d\n%s\n%s", code, short, exitcode.GateExceeded, out, errOut)
	}
}

// shortName is the 8.3 name of a directory in the working directory, or
// its own name when the volume makes none.
func shortName(t *testing.T, dir string) string {
	t.Helper()
	long, err := syscall.UTF16PtrFromString(filepath.Join(mustGetwd(t), dir))
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]uint16, syscall.MAX_PATH)
	n, err := syscall.GetShortPathName(long, &buf[0], uint32(len(buf)))
	if err != nil || n == 0 || int(n) > len(buf) {
		t.Fatalf("GetShortPathName: %v", err)
	}
	return filepath.Base(syscall.UTF16ToString(buf[:n]))
}

func mustGetwd(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return wd
}
