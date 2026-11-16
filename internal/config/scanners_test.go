package config

import (
	"slices"
	"strings"
	"testing"
)

// Protection tests for #221 (ADR 0013, #62 subset): enabling a scanner runs
// a program on the host, so the scanned repository's creep.yaml may only
// remove scanners that an operator layer enabled.

func TestProjectMayOnlyRemoveScanners(t *testing.T) {
	tests := []struct {
		name       string
		in         Inputs
		want       []string
		wantSource string
		wantErr    string
	}{
		{"project enables from the default", Inputs{Project: file("creep.yaml", "scanners:\n  enabled: [gitleaks]\n")},
			nil, "", `project "creep.yaml": key "scanners.enabled" cannot enable "gitleaks"`},
		{"project adds to the user's list", Inputs{
			User:    file("u.yaml", "scanners:\n  enabled: [gitleaks]\n"),
			Project: file("creep.yaml", "scanners:\n  enabled: [gitleaks, semgrep]\n"),
		}, nil, "", `cannot enable "semgrep"`},
		{"project adds to the policy's list", Inputs{
			Policy:  file("org.yaml", "defaults:\n  scanners:\n    enabled: [osv-scanner]\n"),
			Project: file("creep.yaml", "scanners:\n  enabled: [gitleaks]\n"),
		}, nil, "", `cannot enable "gitleaks"`},
		{"project removes one", Inputs{
			User:    file("u.yaml", "scanners:\n  enabled: [gitleaks, osv-scanner]\n"),
			Project: file("creep.yaml", "scanners:\n  enabled: [osv-scanner]\n"),
		}, []string{"osv-scanner"}, `project "creep.yaml"`, ""},
		{"project removes all", Inputs{
			User:    file("u.yaml", "scanners:\n  enabled: [gitleaks]\n"),
			Project: file("creep.yaml", "scanners:\n  enabled: []\n"),
		}, []string{}, `project "creep.yaml"`, ""},
		{"project keeps the same list", Inputs{
			Policy:  file("org.yaml", "defaults:\n  scanners:\n    enabled: [gitleaks]\n"),
			Project: file("creep.yaml", "scanners:\n  enabled: [gitleaks]\n"),
		}, []string{"gitleaks"}, `project "creep.yaml"`, ""},
		{"user enables", Inputs{User: file("u.yaml", "scanners:\n  enabled: [semgrep]\n")},
			[]string{"semgrep"}, `user "u.yaml"`, ""},
		{"policy enables", Inputs{Policy: file("org.yaml", "defaults:\n  scanners:\n    enabled: [gitleaks]\n")},
			[]string{"gitleaks"}, `policy "org.yaml"`, ""},
		{"--config enables", Inputs{Explicit: file("ci.yaml", "scanners:\n  enabled: [gitleaks]\n")},
			[]string{"gitleaks"}, `--config "ci.yaml"`, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, err := Load(tc.in)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
				}
				return
			}
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
