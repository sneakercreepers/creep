package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sneakercreepers/creep/internal/exitcode"
)

// Regression (#341 tester findings 1 and 2): a finished step is served
// only with the reply the run got. When a later --record scan rewrote the
// shared cache, or the cache is gone, the resume is refused (exit 2, no end
// line, no new call) instead of reporting another scan's replies.
func TestResumeRefusesRewrittenRecording(t *testing.T) {
	tests := []struct {
		name   string
		change func(t *testing.T, cfg string)
	}{
		{"another scan recorded over it", func(t *testing.T, cfg string) {
			if code, _, errOut := runScanWith(tierMDeps(newCutModel(nil, "", 0)), "scan", "--record", "--config", cfg); code != exitcode.OK {
				t.Fatalf("scan B exit %d: %s", code, errOut)
			}
		}},
		{"cache removed", func(t *testing.T, _ string) {
			if err := os.RemoveAll(filepath.Join(stateDir, "cache")); err != nil {
				t.Fatal(err)
			}
		}},
	}
	files := resumeFiles(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, id := killedRun(t, files, "", tierMDeps)
			tt.change(t, cfg)
			m := newCutModel(sqliVulnerable, "", 0)
			code, out, errOut := runScanWith(tierMDeps(m), "resume", id, "--config", cfg)
			if code != exitcode.ConfigError || out != "" || len(m.bodies) != 0 || !strings.Contains(errOut, "rewritten by a later scan") {
				t.Fatalf("exit %d after %d calls, stdout %q: %s; want exit 2 and nothing sent", code, len(m.bodies), out, errOut)
			}
			if _, err := loadResumable(id); err != nil {
				t.Fatalf("the refused run was ended or damaged: %v", err)
			}
		})
	}
}

// --baseline enters the header with its entries, not only its path, so a
// baseline edited after the kill is refused (#341 tester finding 4).
func TestResumeRefusesEditedBaseline(t *testing.T) {
	path := filepath.Join(t.TempDir(), "baseline.json")
	rewrite(t, path, `{"version": 1, "entries": []}`)
	cfg, id := killedRun(t, resumeFiles(t), "", tierMDeps, "--baseline", path)
	rewrite(t, path, `{"version": 1, "entries": [{"kind": "accepted", "fingerprint": "0123456789abcdef0123456789abcdef", "class": "sqli", "path": "app.py", "expires": "2027-01-01", "reason": "r"}]}`)
	m := newCutModel(sqliVulnerable, "", 0)
	code, _, errOut := runScanWith(tierMDeps(m), "resume", id, "--config", cfg, "--baseline", path)
	if code != exitcode.ConfigError || len(m.bodies) != 0 || !strings.Contains(errOut, "--baseline and its entries") {
		t.Fatalf("exit %d after %d calls: %s; want the edited baseline refused", code, len(m.bodies), errOut)
	}
}
