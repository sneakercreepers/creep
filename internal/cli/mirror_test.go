package cli

import (
	"strings"
	"testing"

	"github.com/sneakercreepers/creep/internal/calibrate"
	"github.com/sneakercreepers/creep/internal/config"
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

// TestMirrorRulesMatchConfig keeps config's check of sandbox.mirror and
// the sandbox's own (Mirror.Valid, run again before each build) in step:
// the two copies of the rules must accept and refuse the same values, so
// a drift in either shows here instead of as a mirror the operator was
// told is fine and every build then refuses, or the reverse.
func TestMirrorRulesMatchConfig(t *testing.T) {
	bridges := []string{"creep-mirror", "Mirror_1.net", "host", "HOST", "none", "Pasta", "ns", "container", "--network=host",
		"ns:/proc/1/ns/net", "container:abc", "a b", "-x", ".x", strings.Repeat("a", 64), strings.Repeat("a", 65)}
	proxies := []string{"", "http://mirror", "https://10.89.0.2:3128/", "http://169.254.169.254", "http://localhost:3128",
		"http://u:p@mirror:3128", "http://mirror:3128/x", "http://mirror:3128?a=b", "socks5://mirror:1080", "file:///etc/passwd",
		"http://[::1]:3128", "mirror:3128", "http://-mirror", "http://:3128", "http://mirror:123456", "HTTP://mirror"}
	for _, b := range bridges {
		for _, p := range proxies {
			yaml := "sandbox:\n  mirror:\n    bridge: \"" + b + "\"\n    proxy: \"" + p + "\"\n"
			_, err := config.Load(config.Inputs{User: &config.File{Name: "u", Data: []byte(yaml)}})
			if loaded, valid := err == nil, (sandbox.Mirror{Bridge: b, Proxy: p}).Valid(); loaded != valid {
				t.Errorf("bridge %q proxy %q: config accepts %v, sandbox accepts %v", b, p, loaded, valid)
			}
		}
	}
}
