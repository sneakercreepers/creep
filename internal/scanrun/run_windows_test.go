//go:build windows

package scanrun

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/sneakercreepers/creep/internal/static"
)

// TestRunRefusesJunctionIntoRepo covers PR #218 tester finding 1: a
// junction outside the repository that points into it is followed to its
// final path and refused, both through detection and by the runner, and
// neither a \\?\ spelling nor a .cmd file starts anything.
func TestRunRefusesJunctionIntoRepo(t *testing.T) {
	base := t.TempDir()
	repo, outside := filepath.Join(base, "repo"), filepath.Join(base, "outside")
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	bin := installFake(t, filepath.Join(repo, "tools"), "findings", "gitleaks")
	junction := filepath.Join(outside, "j")
	// mklink is a cmd built-in; the test, not the runner, uses the shell.
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", junction, filepath.Dir(bin)).CombinedOutput(); err != nil {
		t.Skipf("mklink /J: %v: %s", err, out)
	}
	viaJunction := filepath.Join(junction, filepath.Base(bin))
	for _, b := range []string{viaJunction, `\\?\` + viaJunction} {
		got := Run(context.Background(), Job{Scanner: static.ScannerGitleaks, Bin: b, Repo: repo, Limits: testLimits()})
		if got.Outcome != Refused {
			t.Errorf("Run(%q) = %+v, want refused", b, got)
		}
	}
	checks := static.DetectScanners([]string{"gitleaks"}, static.ScannerEnv{Path: junction, Repo: repo})
	if checks[0].State != static.ScannerRefused {
		t.Errorf("detection through the junction = %+v, want refused", checks[0])
	}
	if ran(bin) {
		t.Error("the binary was started")
	}
}

func TestRunRefusesNonExe(t *testing.T) {
	base := t.TempDir()
	repo := filepath.Join(base, "repo")
	if err := os.Mkdir(repo, 0o700); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(base, "gitleaks.cmd")
	if err := os.WriteFile(script, []byte("@echo off\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := Run(context.Background(), Job{Scanner: static.ScannerGitleaks, Bin: script, Repo: repo, Limits: testLimits()})
	if got.Outcome != Refused {
		t.Fatalf("Run(.cmd) = %+v, want refused", got)
	}
}
