package config

import (
	"slices"
	"strings"
	"testing"
)

// TestPolicyRecipeSources: only the policy file sets recipe_sources (ADR
// 0028); an absent list is not enforced, an empty one is, and no user,
// project or --config file can name it.
func TestPolicyRecipeSources(t *testing.T) {
	tests := []struct {
		policy   string
		want     []string
		enforced bool
	}{
		{"locked: []\n", nil, false},
		{"recipe_sources: []\n", []string{}, true},
		{"recipe_sources: [github.com/acme/recipes, \"github.com/org/*\"]\n", []string{"github.com/acme/recipes", "github.com/org/*"}, true},
	}
	for _, tt := range tests {
		r, err := Load(Inputs{Policy: &File{Name: "policy.yaml", Data: []byte(tt.policy)}})
		if err != nil {
			t.Fatalf("%q: %v", tt.policy, err)
		}
		got, enforced := r.PolicyRecipeSources()
		if enforced != tt.enforced || !slices.Equal(got, tt.want) {
			t.Errorf("%q: got %v, %v; want %v, %v", tt.policy, got, enforced, tt.want, tt.enforced)
		}
	}
	if _, err := Load(Inputs{Policy: &File{Name: "p", Data: []byte("recipe_sources:\n")}}); err == nil {
		t.Error("a null recipe_sources loaded")
	}
	layer := &File{Name: "creep.yaml", Data: []byte("recipe_sources: [\"github.com/acme/*\"]\n")}
	for name, in := range map[string]Inputs{"user": {User: layer}, "project": {Project: layer}, "--config": {Explicit: layer}} {
		if _, err := Load(in); err == nil || !strings.Contains(err.Error(), `unknown key "recipe_sources"`) {
			t.Errorf("%s file naming recipe_sources: %v", name, err)
		}
	}
}
