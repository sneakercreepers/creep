package testapps

import (
	"slices"
	"testing"

	"github.com/sneakercreepers/creep/internal/calibrate"
	"github.com/sneakercreepers/creep/internal/report"
)

// TestClassesMatchCalibrate keeps the answer key's classes in step with the
// product (#158): each one is a class calibration scores or one every
// report lists as not looked for (idor, missing_auth and prototype_pollution
// since #358), so an expected finding never names a class creep does not
// know.
func TestClassesMatchCalibrate(t *testing.T) {
	if unknown := unknownClasses(classes, knownClasses()); len(unknown) != 0 {
		t.Errorf("testapps classes neither calibrated nor listed as not looked for: %v", unknown)
	}
}

func knownClasses() []string {
	var known []string
	for _, c := range calibrate.Classes() {
		known = append(known, string(c))
	}
	for _, n := range report.NotLookedForClasses() {
		known = append(known, n.Class)
	}
	return known
}

func TestUnknownClasses(t *testing.T) {
	tests := []struct {
		name  string
		local map[string]bool
		known []string
		want  []string
	}{
		{"all known", map[string]bool{"sqli": true, "idor": true}, []string{"idor", "sqli", "xss"}, nil},
		{"both empty", map[string]bool{}, nil, nil},
		{"renamed class", map[string]bool{"sql_injection": true}, []string{"sqli"}, []string{"sql_injection"}},
		{"case differs", map[string]bool{"SQLi": true, "ssrf": true}, []string{"sqli", "ssrf"}, []string{"SQLi"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := unknownClasses(tt.local, tt.known); !slices.Equal(got, tt.want) {
				t.Errorf("unknownClasses = %q, want %q", got, tt.want)
			}
		})
	}
}

// unknownClasses lists, sorted, every local class known does not hold.
func unknownClasses(local map[string]bool, known []string) []string {
	var out []string
	for c := range local {
		if !slices.Contains(known, c) {
			out = append(out, c)
		}
	}
	slices.Sort(out)
	return out
}
