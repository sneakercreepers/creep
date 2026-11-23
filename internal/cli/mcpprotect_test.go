package cli

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sneakercreepers/creep/internal/calibrate"
	"github.com/sneakercreepers/creep/internal/exitcode"
	"github.com/sneakercreepers/creep/internal/sandbox"
	"github.com/sneakercreepers/creep/internal/scanrun"
)

// mcpRepo is scanRepo with every directory a scan could write to outside
// the repository isolated and returned: the user's config and cache
// directories, the temporary directory and the config file's directory.
func mcpRepo(t *testing.T, files map[string]string, extraConfig string) (repo, cfg string, roots []string) {
	t.Helper()
	cfg = scanRepo(t, files, extraConfig)
	home, tmp := t.TempDir(), t.TempDir()
	for _, v := range []string{"XDG_CONFIG_HOME", "XDG_CACHE_HOME", "AppData", "LocalAppData", "HOME", "USERPROFILE"} {
		t.Setenv(v, home)
	}
	for _, v := range []string{"TMPDIR", "TMP", "TEMP"} {
		t.Setenv(v, tmp)
	}
	repo, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return repo, cfg, []string{repo, home, tmp, filepath.Dir(cfg)}
}

// Protection, acceptance (#32): no MCP tool writes outside .creep/. After a
// CLI scan has created the user's state key, an MCP scan, findings and why
// change nothing outside .creep/ in the repository, the user's config and
// cache directories, the temporary directory or beside the config file;
// before any CLI scan, the MCP scan refuses rather than create the key.
// The last step proves the tree comparison sees a write.
func TestMCPWritesOnlyUnderCreep(t *testing.T) {
	repo, cfg, roots := mcpRepo(t, map[string]string{"app.py": "@flask", "lib/jobs.py": "import os\n"}, "")
	creepDir := filepath.Join(repo, stateDir)
	deps := fakeDeps(&fakeModel{verdict: sqliVulnerable}, calibrate.TierM)

	before := treeState(t, roots...)
	c := startMCP(t, deps, "--config", cfg)
	text, isErr := c.tool("scan", map[string]any{"changed": []string{"app.py"}})
	if !isErr || !strings.Contains(text, "state key") {
		t.Errorf("scan before any CLI scan: error %v, %s; want a refusal naming the state key", isErr, text)
	}
	if code := c.stop(); code != exitcode.OK {
		t.Fatalf("creep mcp exit %d: %s", code, c.stderr)
	}
	if got := changedOutside(before, treeState(t, roots...), ""); len(got) > 0 {
		t.Fatalf("the refused MCP scan wrote %v", got)
	}

	if code, out, errOut := runScanWith(deps, "--config", cfg, "scan"); code != exitcode.GateExceeded {
		t.Fatalf("CLI scan: exit %d\n%s%s", code, out, errOut)
	}
	before = treeState(t, roots...)
	c = startMCP(t, deps, "--config", cfg)
	text, isErr = c.tool("scan", map[string]any{"changed": []string{"app.py"}})
	if isErr || !strings.Contains(text, `"outcome":"gate_exceeded"`) {
		t.Fatalf("MCP scan: error %v, %s", isErr, text)
	}
	for _, call := range []struct {
		name string
		args map[string]any
	}{{"findings", map[string]any{}}, {"why", map[string]any{"id": firstFindingID(t, text)}}} {
		if out, isErr := c.tool(call.name, call.args); isErr {
			t.Errorf("%s: %s", call.name, out)
		}
	}
	if code := c.stop(); code != exitcode.OK {
		t.Fatalf("creep mcp exit %d: %s", code, c.stderr)
	}
	after := treeState(t, roots...)
	if got := changedOutside(before, after, creepDir); len(got) > 0 {
		t.Errorf("MCP tools wrote outside .creep/: %v", got)
	}
	if len(changedOutside(before, after, "")) == 0 {
		t.Error("the MCP scan changed nothing under .creep/ either; it did not run")
	}

	writeFile(t, filepath.Join(roots[1], "planted"), "x")
	if len(changedOutside(after, treeState(t, roots...), creepDir)) == 0 {
		t.Error("the tree comparison missed a write outside .creep/")
	}
}

func firstFindingID(t *testing.T, scanReply string) string {
	t.Helper()
	var res struct {
		Findings []struct{ ID string } `json:"findings"`
	}
	if err := json.Unmarshal([]byte(scanReply), &res); err != nil || len(res.Findings) == 0 {
		t.Fatalf("scan reply holds no finding: %v %s", err, scanReply)
	}
	return res.Findings[0].ID
}

// Protection, acceptance (#32): no MCP tool starts a container, runs a PoC
// or an optional scanner, or runs a calibration. With sandbox.enabled, a
// usable runtime and a scheduled CI run (which picks nightly mode), the
// MCP scan detects no runtime, opens no sandbox, builds nothing and runs
// no scanner, and its calibration is cache-only. The CLI row proves the
// same deps would open the sandbox.
func TestMCPStartsNoContainer(t *testing.T) {
	_, cfg, _ := mcpRepo(t, map[string]string{"app.py": "@flask"}, sandboxOn+"scanners:\n  enabled: [gitleaks]\n")
	fb := &fakeBuilder{app: builtApp}
	opened, detected, scanners := 0, 0, 0
	var cacheOnly []bool
	deps := withBuilder(fakeDeps(&fakeModel{verdict: sqliVulnerable}, calibrate.TierM), fb, nil, &opened)
	detect := deps.sandbox.detect
	deps.sandbox.detect = func(ctx context.Context, env sandbox.Env) sandbox.Report {
		detected++
		return detect(ctx, env)
	}
	deps.runScanner = func(context.Context, scanrun.Job) scanrun.Result {
		scanners++
		return scanrun.Result{Outcome: scanrun.NotRun}
	}
	fixed := deps.calibrate
	deps.calibrate = func(ctx context.Context, o calibrate.CacheOptions) (calibrate.Calibration, error) {
		cacheOnly = append(cacheOnly, o.CacheOnly)
		return fixed(ctx, o)
	}
	deps.getenv = ciEnv(scheduledRun)

	if code, out, errOut := runScanWith(deps, "--config", cfg, "scan"); code == exitcode.ConfigError || opened != 1 || detected != 1 {
		t.Fatalf("control: the CLI nightly scan exit %d, opened %d, detected %d\n%s%s", code, opened, detected, out, errOut)
	}
	opened, detected, scanners, fb.builds, cacheOnly = 0, 0, 0, 0, nil
	c := startMCP(t, deps, "--config", cfg)
	text, isErr := c.tool("scan", map[string]any{"changed": []string{"app.py"}})
	if code := c.stop(); isErr || code != exitcode.OK {
		t.Fatalf("MCP scan: error %v, exit %d: %s %s", isErr, code, text, c.stderr)
	}
	if opened != 0 || detected != 0 || fb.builds != 0 || fb.exchanges != 0 || scanners != 0 {
		t.Errorf("the MCP scan reached the sandbox or a scanner: opened %d, detected %d, builds %d, exchanges %d, scanners %d",
			opened, detected, fb.builds, fb.exchanges, scanners)
	}
	if len(cacheOnly) != 1 || !cacheOnly[0] {
		t.Errorf("calibration cache-only flags %v, want one cache-only lookup", cacheOnly)
	}
	if !strings.Contains(text, `"outcome":"gate_exceeded"`) {
		t.Errorf("the MCP scan did not scan: %s", text)
	}
}

// A cache-only calibration never runs the model or writes the cache.
func TestCacheOnlyCalibrationRefusesMiss(t *testing.T) {
	isolateUserConfig(t)
	cache := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", cache)
	t.Setenv("LocalAppData", cache)
	t.Setenv("HOME", cache)
	_, err := calibrateWithUserCache(context.Background(), calibrate.CacheOptions{CacheOnly: true})
	if !errors.Is(err, calibrate.ErrNotCached) {
		t.Fatalf("err %v, want ErrNotCached", err)
	}
	if entries, _ := os.ReadDir(cache); len(entries) != 0 {
		t.Errorf("the cache-only lookup created %v", entries)
	}
}
