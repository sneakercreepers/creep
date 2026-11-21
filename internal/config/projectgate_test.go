package config

import (
	"regexp"
	"strings"
	"testing"
)

// Protection (#249): the project file's gate floor is the stricter of the
// built-in gate, the policy limit and the gate the layers before it set, so
// a hostile creep.yaml cannot hand back the built-in gate to an operator who
// tightened it. Operator layers may still loosen.
func TestProjectCannotLoosenInheritedGate(t *testing.T) {
	user := func(yaml string) *File { return file("~/.creep/config.yaml", yaml) }
	project := func(yaml string) *File { return file("creep.yaml", yaml) }
	policy := func(yaml string) *File { return file("org.yaml", yaml) }
	const hint = "; the project file may only make gates stricter"
	tests := []struct {
		name      string
		in        Inputs
		key, want string // want is the value, or the error with wantErr; a trailing $ anchors it at the end
		wantErr   bool
	}{
		{"pr looser than user", Inputs{User: user("gates:\n  pr: probable:medium\n"), Project: project("gates:\n  pr: probable:critical\n")},
			"gates.pr", `project "creep.yaml": gates.pr "probable:critical" is looser than the gate "probable:medium" set by user "~/.creep/config.yaml"` + hint, true},
		{"pr equal to user", Inputs{User: user("gates:\n  pr: probable:medium\n"), Project: project("gates:\n  pr: probable:medium\n")}, "gates.pr", "probable:medium", false},
		{"pr stricter than user", Inputs{User: user("gates:\n  pr: probable:medium\n"), Project: project("gates:\n  pr: probable:low\n")}, "gates.pr", "probable:low", false},
		{"pr looser status, stricter severity", Inputs{User: user("gates:\n  pr: probable:medium\n"), Project: project("gates:\n  pr: verified:info\n")},
			"gates.pr", `gates.pr "verified:info" is looser than the gate "probable:medium" set by user`, true},
		{"pr disabled over user", Inputs{User: user("gates:\n  pr: probable:high\n"), Project: project("gates:\n  pr: none\n")},
			"gates.pr", `gates.pr "none" is looser than the gate "probable:high" set by user`, true},
		{"nightly looser than user", Inputs{User: user("gates:\n  nightly: probable:high\n"), Project: project("gates:\n  nightly: verified:high\n")},
			"gates.nightly", `project "creep.yaml": gates.nightly "verified:high" is looser than the gate "probable:high" set by user "~/.creep/config.yaml"` + hint, true},
		{"nightly equal to user", Inputs{User: user("gates:\n  nightly: probable:high\n"), Project: project("gates:\n  nightly: probable:high\n")}, "gates.nightly", "probable:high", false},
		{"nightly stricter than user", Inputs{User: user("gates:\n  nightly: probable:high\n"), Project: project("gates:\n  nightly: probable:low\n")}, "gates.nightly", "probable:low", false},
		{"user gate on pr does not floor nightly", Inputs{User: user("gates:\n  pr: probable:low\n"), Project: project("gates:\n  nightly: verified:high\n")}, "gates.nightly", "verified:high", false},
		{"policy default floors pr", Inputs{Policy: policy("defaults:\n  gates:\n    pr: probable:medium\n"), Project: project("gates:\n  pr: probable:critical\n")},
			"gates.pr", `gates.pr "probable:critical" is looser than the gate "probable:medium" set by policy "org.yaml"` + hint, true},
		{"policy default floors nightly", Inputs{Policy: policy("defaults:\n  gates:\n    nightly: verified:low\n"), Project: project("gates:\n  nightly: verified:high\n")},
			"gates.nightly", `gates.nightly "verified:high" is looser than the gate "verified:low" set by policy "org.yaml"`, true},
		{"user overrides policy default", Inputs{Policy: policy("defaults:\n  gates:\n    pr: probable:low\n"), User: user("gates:\n  pr: probable:high\n"), Project: project("gates:\n  pr: probable:high\n")}, "gates.pr", "probable:high", false},
		{"user loosened: built-in floor holds", Inputs{User: user("gates:\n  pr: none\n"), Project: project("gates:\n  pr: verified:critical\n")},
			"gates.pr", `gates.pr "verified:critical" is looser than the built-in floor "probable:critical" set by default` + hint, true},
		{"user loosened: built-in gate accepted", Inputs{User: user("gates:\n  pr: none\n"), Project: project("gates:\n  pr: probable:critical\n")}, "gates.pr", "probable:critical", false},
		{"user stricter than limit is named", Inputs{Policy: policy("limits:\n  gates:\n    pr: probable:high\n"), User: user("gates:\n  pr: probable:low\n"), Project: project("gates:\n  pr: probable:medium\n")},
			"gates.pr", `gates.pr "probable:medium" is looser than the gate "probable:low" set by user`, true},
		{"limit stricter than user is named", Inputs{Policy: policy("limits:\n  gates:\n    pr: probable:low\n"), User: user("gates:\n  pr: probable:medium\n"), Project: project("gates:\n  pr: probable:high\n")},
			"gates.pr", `gates.pr "probable:high" is looser than the limit "probable:low" set by policy "org.yaml"`, true},
		{"unordered floors are all named with a gate that meets them", Inputs{User: user("gates:\n  pr: verified:low\n"), Project: project("gates:\n  pr: verified:critical\n")},
			"gates.pr", `project "creep.yaml": gates.pr "verified:critical" is looser than the gate "verified:low" set by user "~/.creep/config.yaml" and the built-in floor "probable:critical" set by default; the project file may only make gates stricter, use "probable:low" or a stricter gate`, true},
		{"the suggested gate is accepted", Inputs{User: user("gates:\n  pr: verified:low\n"), Project: project("gates:\n  pr: probable:low\n")}, "gates.pr", "probable:low", false},
		{"unordered limit and user gate", Inputs{Policy: policy("limits:\n  gates:\n    pr: verified:medium\n"), User: user("gates:\n  pr: probable:critical\n"), Project: project("gates:\n  pr: verified:critical\n")},
			"gates.pr", `the limit "verified:medium" set by policy "org.yaml" and the gate "probable:critical" set by user "~/.creep/config.yaml" and the built-in floor "probable:critical" set by default; the project file may only make gates stricter, use "probable:medium"`, true},
		{"one broken floor: suggestion also meets the built-in floor", Inputs{User: user("gates:\n  pr: verified:low\n"), Project: project("gates:\n  pr: probable:medium\n")},
			"gates.pr", `gates.pr "probable:medium" is looser than the gate "verified:low" set by user "~/.creep/config.yaml"; the project file may only make gates stricter, use "probable:low" or a stricter gate`, true},
		{"nightly: suggestion keeps the project's stricter status", Inputs{User: user("gates:\n  nightly: verified:info\n"), Project: project("gates:\n  nightly: probable:high\n")},
			"gates.nightly", `use "probable:info" or a stricter gate`, true},
		{"limit broken: no operator hint", Inputs{Policy: policy("limits:\n  gates:\n    pr: verified:low\n"), Project: project("gates:\n  pr: probable:medium\n")},
			"gates.pr", `gates.pr "probable:medium" is looser than the limit "verified:low" set by policy "org.yaml"; the project file may only make gates stricter, use "probable:low" or a stricter gate`, true},
		{"unordered limit and built-in floor are both named", Inputs{Policy: policy("limits:\n  gates:\n    pr: verified:low\n"), Project: project("gates:\n  pr: verified:critical\n")},
			"gates.pr", `gates.pr "verified:critical" is looser than the limit "verified:low" set by policy "org.yaml" and the built-in floor "probable:critical" set by default; the project file may only make gates stricter, use "probable:low" or a stricter gate`, true},
		{"operator hint names the layer that set the gate", Inputs{User: user("gates:\n  pr: probable:low\n"), Project: project("gates:\n  pr: probable:high\n")},
			"gates.pr", `use "probable:low" or a stricter gate, or set a looser gate in user "~/.creep/config.yaml"`, true},
		{"operator hint names a policy default", Inputs{Policy: policy("defaults:\n  gates:\n    pr: probable:low\n"), Project: project("gates:\n  pr: probable:high\n")},
			"gates.pr", `use "probable:low" or a stricter gate, or set a looser gate in policy "org.yaml"`, true},
		{"built-in floor broken: no operator hint", Inputs{User: user("gates:\n  pr: none\n"), Project: project("gates:\n  pr: verified:critical\n")},
			"gates.pr", `gates.pr "verified:critical" is looser than the built-in floor "probable:critical" set by default; the project file may only make gates stricter, use "probable:critical" or a stricter gate$`, true},
		{"stricter user gate hides a broken built-in floor: no operator hint", Inputs{User: user("gates:\n  pr: probable:low\n"), Project: project("gates:\n  pr: none\n")},
			"gates.pr", `gates.pr "none" is looser than the gate "probable:low" set by user "~/.creep/config.yaml"; the project file may only make gates stricter, use "probable:low" or a stricter gate$`, true},
		{"locked pr cannot be restated", Inputs{Policy: policy("locked: [gates.pr]\ndefaults:\n  gates:\n    pr: probable:medium\n"), Project: project("gates:\n  pr: probable:medium\n")},
			"gates.pr", `key "gates.pr" is locked by policy "org.yaml"`, true},
		{"locked pr, nightly still floored", Inputs{Policy: policy("locked: [gates.pr]\n"), User: user("gates:\n  nightly: probable:high\n"), Project: project("gates:\n  nightly: verified:high\n")},
			"gates.nightly", `gates.nightly "verified:high" is looser than the gate "probable:high" set by user`, true},
		{"--config replaces the project file", Inputs{Explicit: file("ci.yaml", "gates:\n  pr: probable:medium\n"), Project: project("gates:\n  pr: none\n")}, "gates.pr", "probable:medium", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := Load(tt.in)
			if tt.wantErr {
				want, anchored := strings.CutSuffix(tt.want, "$")
				if err == nil || !strings.Contains(err.Error(), want) || anchored && !strings.HasSuffix(err.Error(), want) {
					t.Fatalf("err = %v, want containing %q", err, tt.want)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got := field(&r.Config, tt.key).String(); got != tt.want {
				t.Errorf("%s = %q, want %q", tt.key, got, tt.want)
			}
		})
	}
}

// Every gate the error suggests passes: for each user gate or policy limit
// and each project gate, a rejected project gate names a gate that Load
// then accepts at the same layers. The operator hint appears exactly when
// following it passes: setting the user gate to the project's value (#249,
// auditor A1; #64). A policy limit, which no operator layer loosens, never
// gets the hint.
func TestSuggestedProjectGateIsAccepted(t *testing.T) {
	gates := []string{gateNone}
	for _, st := range gateStatuses {
		for _, sv := range gateSeverities {
			gates = append(gates, st+":"+sv)
		}
	}
	suggestion := regexp.MustCompile(`use "([^"]+)" or a stricter gate`)
	for _, layer := range []string{"user", "limit"} {
		inputs := func(floor, project string) Inputs {
			in := Inputs{Project: file("creep.yaml", "gates:\n  pr: "+project+"\n")}
			if layer == "user" {
				in.User = file("u", "gates:\n  pr: "+floor+"\n")
			} else {
				in.Policy = file("org.yaml", "limits:\n  gates:\n    pr: "+floor+"\n")
			}
			return in
		}
		for _, floor := range gates {
			for _, value := range gates {
				checkSuggestion(t, suggestion, inputs, layer, floor, value)
			}
		}
	}
}

func checkSuggestion(t *testing.T, suggestion *regexp.Regexp, inputs func(floor, project string) Inputs, layer, floor, value string) {
	t.Helper()
	name := layer + " " + floor + ", project " + value
	_, err := Load(inputs(floor, value))
	if err == nil {
		return
	}
	m := suggestion.FindStringSubmatch(err.Error())
	if m == nil {
		t.Fatalf("%s: no suggestion in %v", name, err)
	}
	if _, err := Load(inputs(floor, m[1])); err != nil {
		t.Errorf("%s: suggested %s fails: %v", name, m[1], err)
	}
	_, loosened := Load(inputs(value, value))
	wantHint := layer == "user" && loosened == nil
	if hinted := strings.Contains(err.Error(), "set a looser gate"); hinted != wantHint {
		t.Errorf("%s: operator hint %v, want %v: %v", name, hinted, wantHint, err)
	}
	// No gate flag exists, so the hint must not offer one (#64).
	if strings.Contains(err.Error(), "flag") {
		t.Errorf("%s: hint offers a flag: %v", name, err)
	}
}
