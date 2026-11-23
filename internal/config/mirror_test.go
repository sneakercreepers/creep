package config

import (
	"strings"
	"testing"
)

const mirrorYAML = "sandbox:\n  mirror:\n    bridge: creep-mirror\n    proxy: http://mirror.internal:3128\n"

// TestProjectCannotSetBuildMirror is the protection test for ADR 0029: the
// build mirror gives the app build a network, so only the operator's
// layers (user file, --config, policy, a flag) may set it. The scanned
// repository's ./creep.yaml cannot, not even one key of it, and not even
// when an operator layer already set the same value.
func TestProjectCannotSetBuildMirror(t *testing.T) {
	project := map[string]string{
		"sandbox.mirror.bridge": "sandbox:\n  mirror:\n    bridge: creep-mirror\n",
		"sandbox.mirror.proxy":  "sandbox:\n  mirror:\n    proxy: http://mirror.internal:3128\n",
	}
	for key, yaml := range project {
		for name, in := range map[string]Inputs{
			"alone":          {Project: file("creep.yaml", yaml)},
			"after user":     {User: file("u", mirrorYAML), Project: file("creep.yaml", yaml)},
			"after a policy": {Policy: file("p", policyDefaults(mirrorYAML)), Project: file("creep.yaml", yaml)},
		} {
			_, err := Load(in)
			if err == nil || !strings.Contains(err.Error(), `key "`+key+`" cannot be set in the project file`) {
				t.Errorf("%s, %s: err = %v, want refused", key, name, err)
			}
		}
	}
	operator := map[string]Inputs{
		"user":     {User: file("u", mirrorYAML)},
		"--config": {Explicit: file("ci.yaml", mirrorYAML)},
		"policy":   {Policy: file("p", policyDefaults(mirrorYAML))},
		"flags": {Flags: []Flag{
			{Name: "--test-bridge", Key: "sandbox.mirror.bridge", Value: "creep-mirror"},
			{Name: "--test-proxy", Key: "sandbox.mirror.proxy", Value: "http://mirror.internal:3128"},
		}},
	}
	for name, in := range operator {
		r, err := Load(in)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if m := r.Config.Sandbox.Mirror; m.Bridge != "creep-mirror" || m.Proxy != "http://mirror.internal:3128" {
			t.Errorf("%s: mirror = %+v", name, m)
		}
	}
	if m := Defaults().Sandbox.Mirror; m != (Mirror{}) {
		t.Errorf("default mirror = %+v, want none: the build is offline by default", m)
	}
}

func policyDefaults(yaml string) string {
	return "defaults:\n  " + strings.ReplaceAll(strings.TrimSuffix(yaml, "\n"), "\n", "\n  ") + "\n"
}

// TestMirrorValuesChecked refuses a network mode for the bridge (host would
// give build steps the host's network), a name a CLI could read as a flag,
// and a proxy with credentials, a path or another scheme; the error never
// prints a refused proxy, which may hold a credential.
func TestMirrorValuesChecked(t *testing.T) {
	bad := map[string]string{ //nolint:gosec // G101: fake credentials the check must refuse and never print
		"host mode":       "bridge: host",
		"host mode case":  "bridge: HOST",
		"none mode":       "bridge: none",
		"pasta mode":      "bridge: pasta",
		"flag":            "bridge: --network=host",
		"namespace":       "bridge: \"ns:/proc/1/ns/net\"",
		"container":       "bridge: \"container:abc\"",
		"space":           "bridge: \"a b\"",
		"too long":        "bridge: " + strings.Repeat("a", 65),
		"credentials":     "proxy: http://user:s3cr3t@mirror:3128",
		"path":            "proxy: http://mirror:3128/x",
		"query":           "proxy: http://mirror:3128?a=b",
		"scheme":          "proxy: socks5://mirror:1080",
		"no scheme":       "proxy: mirror:3128",
		"line break":      "proxy: \"http://mirror\n:3128\"",
		"leading dash":    "proxy: http://-mirror",
		"empty host":      "proxy: http://:3128",
		"port too long":   "proxy: http://mirror:123456",
		"trailing spaces": "proxy: \"http://mirror \"",
	}
	for name, kv := range bad {
		_, err := Load(Inputs{User: file("u", "sandbox:\n  mirror:\n    "+kv+"\n")})
		if err == nil || !strings.Contains(err.Error(), "invalid") {
			t.Errorf("%s: err = %v, want invalid", name, err)
		}
		if err != nil && strings.Contains(err.Error(), "s3cr3t") {
			t.Errorf("%s: the error prints the proxy's credential: %v", name, err)
		}
	}
	good := []string{"bridge: creep-mirror", "bridge: Mirror_1.net", "proxy: https://10.89.0.2:3128/", "proxy: http://mirror"}
	for _, kv := range good {
		if _, err := Load(Inputs{User: file("u", "sandbox:\n  mirror:\n    "+kv+"\n")}); err != nil {
			t.Errorf("%s: %v", kv, err)
		}
	}
}
