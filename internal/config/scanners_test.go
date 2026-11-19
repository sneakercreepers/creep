package config

import (
	"slices"
	"strings"
	"testing"
)

// Protection tests for #221 (ADR 0013) and #62: enabling a scanner runs a
// program on the host, and removing one drops a class of findings from a
// run that still reads as complete. The scanned repository's creep.yaml
// therefore cannot set scanners.enabled at all, not even to the inherited
// list; operator layers still can.

func TestProjectCannotSetScanners(t *testing.T) {
	const want = `project "creep.yaml": key "scanners.enabled" cannot be set in the project file`
	tests := []struct {
		name string
		in   Inputs
	}{
		{"project enables from the default", Inputs{Project: file("creep.yaml", "scanners:\n  enabled: [gitleaks]\n")}},
		{"project adds to the user's list", Inputs{
			User:    file("u.yaml", "scanners:\n  enabled: [gitleaks]\n"),
			Project: file("creep.yaml", "scanners:\n  enabled: [gitleaks, semgrep]\n"),
		}},
		{"project removes one", Inputs{
			User:    file("u.yaml", "scanners:\n  enabled: [gitleaks, osv-scanner]\n"),
			Project: file("creep.yaml", "scanners:\n  enabled: [osv-scanner]\n"),
		}},
		{"project removes all", Inputs{
			Policy:  file("org.yaml", "defaults:\n  scanners:\n    enabled: [gitleaks]\n"),
			Project: file("creep.yaml", "scanners:\n  enabled: []\n"),
		}},
		{"project keeps the same list", Inputs{
			User:    file("u.yaml", "scanners:\n  enabled: [gitleaks]\n"),
			Project: file("creep.yaml", "scanners:\n  enabled: [gitleaks]\n"),
		}},
		{"project restates the empty default", Inputs{Project: file("creep.yaml", "scanners:\n  enabled: []\n")}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(tc.in)
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("err = %v, want containing %q", err, want)
			}
		})
	}
}

func TestOperatorLayersSetScanners(t *testing.T) {
	tests := []struct {
		name       string
		in         Inputs
		want       []string
		wantSource string
	}{
		{"user enables", Inputs{User: file("u.yaml", "scanners:\n  enabled: [semgrep]\n")},
			[]string{"semgrep"}, `user "u.yaml"`},
		{"policy enables", Inputs{Policy: file("org.yaml", "defaults:\n  scanners:\n    enabled: [gitleaks]\n")},
			[]string{"gitleaks"}, `policy "org.yaml"`},
		{"--config enables", Inputs{Explicit: file("ci.yaml", "scanners:\n  enabled: [gitleaks]\n")},
			[]string{"gitleaks"}, `--config "ci.yaml"`},
		{"user list survives a project file without the key", Inputs{
			User:    file("u.yaml", "scanners:\n  enabled: [gitleaks, osv-scanner]\n"),
			Project: file("creep.yaml", "budget:\n  max_calls: 10\n"),
		}, []string{"gitleaks", "osv-scanner"}, `user "u.yaml"`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, err := Load(tc.in)
			if err != nil {
				t.Fatal(err)
			}
			if got := r.Config.Scanners.Enabled; !slices.Equal(got, tc.want) {
				t.Errorf("scanners.enabled = %q, want %q", got, tc.want)
			}
			if got := explainSource(r, "scanners.enabled"); got != tc.wantSource {
				t.Errorf("explain source = %q, want %q", got, tc.wantSource)
			}
		})
	}
}

func explainSource(r *Resolved, key string) string {
	for _, e := range r.Explain() {
		if e.Key == key {
			return e.Source
		}
	}
	return ""
}
