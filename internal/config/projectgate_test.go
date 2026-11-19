package config

import (
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
		key, want string // want is the value, or the error with wantErr
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
				if err == nil || !strings.Contains(err.Error(), tt.want) {
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
