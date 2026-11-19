package cli

import (
	"fmt"
	"os"
	"testing"

	"github.com/sneakercreepers/creep/internal/calibrate"
	"github.com/sneakercreepers/creep/internal/exitcode"
	"github.com/sneakercreepers/creep/internal/gitindex/gitindextest"
)

// TestScanShortNameAlias (#267 tester H1): git for Windows checks
// node_m~1/app/app.js out into node_modules/app/ once node_modules/ exists,
// so the index tracks the tree under a name the scan never sees. Identity,
// not the name, decides: the committed app is evaluated. Skipped where the
// file system makes no 8.3 names (Linux, macOS, volumes with them off).
func TestScanShortNameAlias(t *testing.T) {
	cfg := scanRepo(t, map[string]string{
		"main.py": helloRoute, "node_modules/.keep": "", "node_modules/app/package.json": "{}", "node_modules/app/app.js": "@express",
	}, "")
	short, ok := shortNameOf("node_modules", "NODE_M")
	if !ok {
		t.Skip("this file system makes no 8.3 names")
	}
	index := gitindextest.Build(gitindextest.Spec{Version: 2, Paths: []string{
		short + "/app/app.js", short + "/app/package.json", "main.py", "node_modules/.keep",
	}})
	writeTreeFile(t, ".", gitIndexPath, string(index))
	m := &fakeModel{verdict: map[string]string{"command_injection": "vulnerable"}}
	code, out, errOut := runScanWith(fakeDeps(m, calibrate.TierM), "scan", "--config", cfg)
	if code != exitcode.GateExceeded {
		t.Fatalf("exit %d with the tree tracked as %s, want %d\n%s\n%s", code, short, exitcode.GateExceeded, out, errOut)
	}
}

// shortNameOf finds the 8.3 name (prefix~N) the file system gives dir in
// the working directory, by trying each and comparing identity.
func shortNameOf(dir, prefix string) (string, bool) {
	want, err := os.Lstat(dir)
	if err != nil {
		return "", false
	}
	for i := 1; i <= 9; i++ {
		name := fmt.Sprintf("%s~%d", prefix, i)
		if got, err := os.Lstat(name); err == nil && os.SameFile(got, want) {
			return name, true
		}
	}
	return "", false
}
