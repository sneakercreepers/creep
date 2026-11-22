package config

import (
	"slices"
	"strings"
	"testing"
)

func env(vars map[string]string) func(string) string {
	return func(name string) string { return vars[name] }
}

func TestChooseMode(t *testing.T) {
	schedule := map[string]string{"GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "schedule"}
	tests := []struct {
		name    string
		flag    string
		env     map[string]string
		want    ModeChoice
		wantErr string
	}{
		{"default", "", nil, ModeChoice{ModePR, "default"}, ""},
		{"flag pr", "pr", nil, ModeChoice{ModePR, "flag --mode"}, ""},
		{"flag nightly", "nightly", nil, ModeChoice{ModeNightly, "flag --mode"}, ""},
		{"scheduled GitHub run", "", schedule, ModeChoice{ModeNightly, "GitHub Actions schedule event"}, ""},
		{"flag wins over the schedule", "pr", schedule, ModeChoice{ModePR, "flag --mode"}, ""},
		{"pull request", "", map[string]string{"GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "pull_request"}, ModeChoice{ModePR, "default"}, ""},
		{"push", "", map[string]string{"GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "push"}, ModeChoice{ModePR, "default"}, ""},
		{"event without GitHub Actions", "", map[string]string{"GITHUB_EVENT_NAME": "schedule"}, ModeChoice{ModePR, "default"}, ""},
		{"other CI", "", map[string]string{"CI": "true", "CI_PIPELINE_SOURCE": "schedule"}, ModeChoice{ModePR, "default"}, ""},
		{"event name case", "", map[string]string{"GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "Schedule"}, ModeChoice{ModePR, "default"}, ""},
		{"unknown flag", "weekly", nil, ModeChoice{}, `invalid --mode "weekly": want one of pr, nightly`},
		{"flag case", "Nightly", nil, ModeChoice{}, "invalid --mode"},
		{"flag control characters", "pr\x1b", nil, ModeChoice{}, `"pr\x1b"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ChooseMode(tt.flag, env(tt.env))
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil || got != tt.want {
				t.Fatalf("ChooseMode = %+v, %v; want %+v", got, err, tt.want)
			}
		})
	}
}

// allGates lists every valid gate value.
func allGates() []string {
	out := []string{gateNone}
	for _, st := range gateStatuses {
		for _, sv := range gateSeverities {
			out = append(out, st+":"+sv)
		}
	}
	return out
}

// Protection (#28, ADR 0021): reading a gate without verification never
// loosens it, whatever the gate: the result fails on every finding the
// gate fails on, keeps the gate's severity, and reads probable findings
// unless the gate is none.
func TestUnverifiedGateNeverLoosens(t *testing.T) {
	for _, value := range allGates() {
		got, err := UnverifiedGate(value)
		if err != nil {
			t.Fatalf("%s: %v", value, err)
		}
		g, _ := parseGate(value)
		u, err := parseGate(got)
		if err != nil {
			t.Fatalf("%s -> %q: %v", value, got, err)
		}
		if !u.atLeastAsStrict(g) {
			t.Errorf("%s -> %s is looser", value, got)
		}
		if g.none != u.none || !g.none && (u.severity != g.severity || gateStatuses[u.status] != "probable") {
			t.Errorf("%s -> %s, want probable at the same severity", value, got)
		}
	}
	for _, bad := range []string{"", "verified", "verified:urgent", "maybe:high"} {
		if _, err := UnverifiedGate(bad); err == nil {
			t.Errorf("%q: no error", bad)
		}
	}
}

func TestUnverifiedGate(t *testing.T) {
	for value, want := range map[string]string{
		"verified:high": "probable:high", "verified:info": "probable:info",
		"probable:critical": "probable:critical", "none": "none",
	} {
		if got, err := UnverifiedGate(value); err != nil || got != want {
			t.Errorf("UnverifiedGate(%q) = %q, %v; want %q", value, got, err, want)
		}
	}
}

// Protection (#28, #61, #249): each mode reads its own key, and the project
// file cannot loosen the key of either mode below the built-in, inherited
// or limit gate, nor pick the mode. The operator layers may, which shows
// the refusal is the project layer's.
func TestProjectCannotLoosenTheModeGate(t *testing.T) {
	tests := []struct {
		name    string
		in      Inputs
		mode    Mode
		want    string // the mode's gate after Load
		source  string
		wantErr string
	}{
		{"built-in pr", Inputs{}, ModePR, "probable:critical", "default", ""},
		{"built-in nightly", Inputs{}, ModeNightly, "verified:high", "default", ""},
		{"project disables nightly", Inputs{Project: file("creep.yaml", "gates:\n  nightly: none\n")}, ModeNightly, "", "",
			`project "creep.yaml": gates.nightly "none" is looser than the built-in floor "verified:high"`},
		{"project raises nightly severity", Inputs{Project: file("creep.yaml", "gates:\n  nightly: verified:critical\n")}, ModeNightly, "", "", "is looser"},
		{"project restores the built-in nightly over the user", Inputs{User: file("u", "gates:\n  nightly: probable:high\n"), Project: file("creep.yaml", "gates:\n  nightly: verified:high\n")}, ModeNightly, "", "",
			`gates.nightly "verified:high" is looser than the gate "probable:high" set by user "u"`},
		{"project loosens below the policy limit", Inputs{Policy: file("org.yaml", "limits:\n  gates:\n    nightly: verified:medium\n"), Project: file("creep.yaml", "gates:\n  nightly: verified:high\n")}, ModeNightly, "", "",
			`is looser than the limit "verified:medium"`},
		{"project picks the mode", Inputs{Project: file("creep.yaml", "mode: pr\n")}, ModeNightly, "", "", `unknown key "mode"`},
		{"policy cannot set a mode either", Inputs{Policy: file("org.yaml", "defaults:\n  mode: pr\n")}, ModeNightly, "", "", `unknown key "defaults.mode"`},
		{"project stricter nightly applies", Inputs{Project: file("creep.yaml", "gates:\n  nightly: probable:high\n")}, ModeNightly, "probable:high", `project "creep.yaml"`, ""},
		{"project nightly leaves pr alone", Inputs{Project: file("creep.yaml", "gates:\n  nightly: probable:high\n")}, ModePR, "probable:critical", "default", ""},
		{"user may loosen nightly", Inputs{User: file("u", "gates:\n  nightly: none\n")}, ModeNightly, "none", `user "u"`, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := Load(tt.in)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if value, source := r.Gate(tt.mode); value != tt.want || source != tt.source {
				t.Errorf("Gate(%s) = %q from %s, want %q from %s", tt.mode, value, source, tt.want, tt.source)
			}
		})
	}
}

// Acceptance (#28): the policy limits apply per mode. The limit of each
// mode floors that mode's gate whichever layer sets it, and the gate a
// nightly scan reads without verification stays at least as strict as the
// limit.
func TestModeGateHonorsLimits(t *testing.T) {
	policy := "defaults:\n  gates:\n    pr: probable:high\n    nightly: verified:medium\nlimits:\n  gates:\n    pr: probable:high\n    nightly: verified:medium\n"
	limits := map[Mode]string{ModePR: "probable:high", ModeNightly: "verified:medium"}
	tests := []struct {
		name    string
		user    string
		mode    Mode
		want    string
		wantErr string
	}{
		{"pr reads the policy default", "", ModePR, "probable:high", ""},
		{"nightly reads the policy default", "", ModeNightly, "verified:medium", ""},
		{"user stricter nightly", "gates:\n  nightly: verified:low\n", ModeNightly, "verified:low", ""},
		{"user looser nightly", "gates:\n  nightly: verified:high\n", ModeNightly, "", `gates.nightly "verified:high" is looser than the limit "verified:medium"`},
		{"user looser pr", "gates:\n  pr: probable:critical\n", ModeNightly, "", `gates.pr "probable:critical" is looser than the limit "probable:high"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := Inputs{Policy: file("org.yaml", policy)}
			if tt.user != "" {
				in.User = file("u", tt.user)
			}
			r, err := Load(in)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			value, _ := r.Gate(tt.mode)
			if value != tt.want {
				t.Fatalf("Gate(%s) = %q, want %q", tt.mode, value, tt.want)
			}
			unverified, err := UnverifiedGate(value)
			if err != nil {
				t.Fatal(err)
			}
			if checkFloor(GateKey(tt.mode), unverified, limits[tt.mode], "the limit", "policy") != nil {
				t.Errorf("unverified gate %q is looser than the limit", unverified)
			}
		})
	}
}

func TestExplainMode(t *testing.T) {
	r, err := Load(Inputs{User: file("u", "gates:\n  nightly: probable:high\n")})
	if err != nil {
		t.Fatal(err)
	}
	got := r.ExplainMode(ModeChoice{ModeNightly, "flag --mode"})
	want := []Entry{
		{Key: "mode", Value: "nightly", Source: "flag --mode"},
		{Key: "gate", Value: "probable:high", Source: `gates.nightly, user "u"`},
		{Key: "gate", Value: "probable:critical", Source: "gates.pr, default"},
	}
	if !slices.Equal(got, want) {
		t.Errorf("ExplainMode = %+v, want %+v", got, want)
	}
}
