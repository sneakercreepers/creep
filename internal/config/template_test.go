package config

import (
	"bytes"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// settingLine is a commented-out YAML line of the template: "# " then a
// lowercase key and a colon. Prose lines never start that way.
var settingLine = regexp.MustCompile(`(?m)^# ( *[a-z_]+:.*)$`)

// uncommented is the template with every setting line switched on.
func uncommented(t *testing.T) []byte {
	t.Helper()
	out := settingLine.ReplaceAll(ProjectTemplate(), []byte("$1"))
	if bytes.Equal(out, ProjectTemplate()) {
		t.Fatal("template has no commented-out setting")
	}
	return out
}

func TestProjectTemplateHeader(t *testing.T) {
	if !bytes.HasPrefix(ProjectTemplate(), []byte("# creep.yaml template v1\n")) {
		t.Fatal("template must start with its version line")
	}
}

// templateV1Keys are the keys template v1 shipped with. Template changes are
// additive only (ADR 0031), so none of them may leave it.
var templateV1Keys = []string{"gates.pr", "gates.nightly", "budget.max_tokens", "budget.max_calls", "budget.max_seconds", "calibration.cache_days", "log.level"}

// TestProjectTemplateKeys derives the refused set from the project layer
// itself: a key it refuses, or a model key, fails the test, and so does a
// key the project layer accepts that the template leaves out.
func TestProjectTemplateKeys(t *testing.T) {
	_, keys, err := decodeConfig(uncommented(t))
	if err != nil {
		t.Fatalf("uncommented template does not decode: %v", err)
	}
	for _, k := range keys {
		if projectForbidden[k] || strings.HasPrefix(k, "model.") {
			t.Errorf("template sets %q, which the project file must not set", k)
		}
	}
	for _, k := range Keys() {
		if projectForbidden[k] || strings.HasPrefix(k, "model.") {
			continue
		}
		if !slices.Contains(keys, k) {
			t.Errorf("template leaves out project key %q", k)
		}
	}
	for _, k := range templateV1Keys {
		if !slices.Contains(keys, k) {
			t.Errorf("template dropped v1 key %q; changes are additive only", k)
		}
	}
}

// TestProjectTemplateValuesAreDefaults switches every setting on: the
// project layer accepts it and no value moves from the built-in default.
func TestProjectTemplateValuesAreDefaults(t *testing.T) {
	got, err := Load(Inputs{Project: &File{Name: "creep.yaml", Data: uncommented(t)}})
	if err != nil {
		t.Fatalf("project layer refuses the uncommented template: %v", err)
	}
	if want := Defaults(); !reflect.DeepEqual(got.Config, want) {
		t.Errorf("uncommented template changes values:\n got %+v\nwant %+v", got.Config, want)
	}
}

// TestProjectTemplateChangesNothing loads each layer stack with and without
// the template as the project file: every value and its source must match.
func TestProjectTemplateChangesNothing(t *testing.T) {
	policy := &File{Name: "policy.yaml", Data: []byte("defaults:\n  gates:\n    pr: probable:high\nlimits:\n  gates:\n    nightly: verified:high\n")}
	user := &File{Name: "~/.creep/config.yaml", Data: []byte("budget:\n  max_tokens: 1000\nlog:\n  level: debug\n")}
	tests := []struct {
		name string
		in   Inputs
	}{
		{"defaults only", Inputs{}},
		{"policy", Inputs{Policy: policy}},
		{"user", Inputs{User: user}},
		{"policy and user", Inputs{Policy: policy, User: user}},
		{"flag", Inputs{User: user, Flags: []Flag{{Name: "--log-level", Key: "log.level", Value: "warn"}}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			without := mustLoad(t, tt.in)
			tt.in.Project = &File{Name: "creep.yaml", Data: ProjectTemplate()}
			with := mustLoad(t, tt.in)
			if !reflect.DeepEqual(with.Explain(), without.Explain()) {
				t.Errorf("template changes effective values:\n with %v\n without %v", with.Explain(), without.Explain())
			}
		})
	}
}

func mustLoad(t *testing.T, in Inputs) *Resolved {
	t.Helper()
	r, err := Load(in)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	return r
}
