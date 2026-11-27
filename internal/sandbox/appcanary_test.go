package sandbox

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

var canaryContent = regexp.MustCompile(`^creep-canary-[0-9a-f]{32}$`)

// TestAppCanaryPlanted is the protection test for the path_payload
// oracle's canary file: StartApp mounts it read-only at AppCanaryFile from
// a file in the 0700 work directory holding exactly AppCanary, fresh
// random content per sandbox, and there is none before StartApp.
func TestAppCanaryPlanted(t *testing.T) {
	seen := map[string]bool{}
	for range 2 {
		rec := withBuilds(networkRecorder(goodCanary, 0), 0)
		before := testSandbox(t, rec)
		if before.AppCanary() != "" {
			t.Errorf("a canary before StartApp: %q", before.AppCanary())
		}
		s := startedApp(t, rec)
		canary := s.AppCanary()
		if !canaryContent.MatchString(canary) || seen[canary] {
			t.Fatalf("canary %q: want fresh creep-canary-<32 hex>", canary)
		}
		seen[canary] = true
		checkCanaryMount(t, s, appRun(t, rec))
	}
}

// appRun is the argv that started the app: the detached run.
func appRun(t *testing.T, rec *recorder) []string {
	t.Helper()
	runs := slices.DeleteFunc(rec.to("run"), func(argv []string) bool { return !slices.Contains(argv, "--detach") })
	if len(runs) != 1 {
		t.Fatalf("%d detached runs, want the app's alone", len(runs))
	}
	return runs[0]
}

func checkCanaryMount(t *testing.T, s *Sandbox, argv []string) {
	t.Helper()
	var mounts []string
	for _, a := range argv {
		if strings.HasPrefix(a, "--mount=") {
			mounts = append(mounts, a)
		}
	}
	// The synthetic env (TestAppGetsSyntheticEnv) is the only other mount.
	if len(mounts) != 2 || !strings.HasSuffix(mounts[0], ",target="+AppCanaryFile+",readonly") ||
		!strings.HasSuffix(mounts[1], ",target=/"+envFileName+",readonly") {
		t.Fatalf("app mounts %q: want the canary and the synthetic env, read-only", mounts)
	}
	src, _, _ := strings.Cut(strings.TrimPrefix(mounts[0], "--mount=type=bind,source="), ",target=")
	if rel, err := filepath.Rel(s.workReal, src); err != nil || !filepath.IsLocal(rel) {
		t.Errorf("canary source %q outside the work directory", src)
	}
	data, err := os.ReadFile(src)
	if err != nil || string(data) != s.AppCanary()+"\n" {
		t.Errorf("canary file %q holds %q, %v", src, data, err)
	}
}
