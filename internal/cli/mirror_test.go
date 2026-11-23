package cli

import (
	"strings"
	"testing"

	"github.com/sneakercreepers/creep/internal/calibrate"
	"github.com/sneakercreepers/creep/internal/sandbox"
)

// TestBuildMirrorReachesSandbox: the operator's sandbox.mirror (here
// --config) reaches the sandbox the scan opens, and the scan says the
// build goes through it; without it the build is offline, the default.
// The project file cannot set it (config.TestProjectCannotSetBuildMirror).
func TestBuildMirrorReachesSandbox(t *testing.T) {
	mirror := "  mirror:\n    bridge: creep-mirror\n    proxy: http://mirror.internal:3128\n"
	tests := []struct {
		name   string
		config string
		want   sandbox.Mirror
		line   string
	}{
		{"offline by default", sandboxOn, sandbox.Mirror{}, "building the app offline with docker"},
		{"operator mirror", sandboxOn + mirror, sandbox.Mirror{Bridge: "creep-mirror", Proxy: "http://mirror.internal:3128"}, "building the app through the operator's mirror (sandbox.mirror) with docker"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fb := &fakeBuilder{app: sandbox.App{Unavailable: sandbox.BuildMirrorRefused, Detail: "builder"}}
			opened := 0
			deps := withBuilder(fakeDeps(&fakeModel{verdict: sqliVulnerable}, calibrate.TierM), fb, nil, &opened)
			_, stdout, stderr := runScanWith(deps, "--config", scanRepo(t, map[string]string{"app.py": "@flask"}, tt.config), "scan", "--mode", "nightly")
			if opened != 1 || fb.mirror != tt.want {
				t.Errorf("opened %d with mirror %+v, want once with %+v", opened, fb.mirror, tt.want)
			}
			if !strings.Contains(stdout+stderr, tt.line) {
				t.Errorf("want %q in output:\n%s%s", tt.line, stdout, stderr)
			}
		})
	}
}
