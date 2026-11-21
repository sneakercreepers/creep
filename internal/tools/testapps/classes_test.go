package testapps

import (
	"slices"
	"testing"

	"github.com/sneakercreepers/creep/internal/calibrate"
)

// TestClassesMatchCalibrate keeps the answer key's classes and the product
// enum calibration scores in step (#158), until both read one shared enum.
func TestClassesMatchCalibrate(t *testing.T) {
	for _, d := range classDrift(classes, calibrate.Classes()) {
		t.Error(d)
	}
}

func TestClassDrift(t *testing.T) {
	tests := []struct {
		name    string
		local   map[string]bool
		product []calibrate.Class
		want    []string
	}{
		{"same set", map[string]bool{"sqli": true, "ssrf": true}, []calibrate.Class{"ssrf", "sqli"}, nil},
		{"both empty", map[string]bool{}, nil, nil},
		{"class only in calibrate", map[string]bool{"sqli": true}, []calibrate.Class{"sqli", "xss"}, []string{"xss: in calibrate.Classes() but not in testapps classes"}},
		{"class only in testapps", map[string]bool{"sqli": true, "xss": true}, []calibrate.Class{"sqli"}, []string{"xss: in testapps classes but not in calibrate.Classes()"}},
		{"renamed class", map[string]bool{"sql_injection": true}, []calibrate.Class{"sqli"}, []string{
			"sql_injection: in testapps classes but not in calibrate.Classes()",
			"sqli: in calibrate.Classes() but not in testapps classes",
		}},
		{"listed twice", map[string]bool{"sqli": true}, []calibrate.Class{"sqli", "sqli"}, []string{"sqli: listed twice by calibrate.Classes()"}},
		{"case differs", map[string]bool{"SQLi": true}, []calibrate.Class{"sqli"}, []string{
			"SQLi: in testapps classes but not in calibrate.Classes()",
			"sqli: in calibrate.Classes() but not in testapps classes",
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classDrift(tt.local, tt.product); !slices.Equal(got, tt.want) {
				t.Errorf("classDrift = %q, want %q", got, tt.want)
			}
		})
	}
}

// classDrift lists, sorted, every class only one side has and every class
// calibrate lists twice.
func classDrift(local map[string]bool, product []calibrate.Class) []string {
	var drift []string
	seen := map[string]bool{}
	for _, c := range product {
		s := string(c)
		if seen[s] {
			drift = append(drift, s+": listed twice by calibrate.Classes()")
		}
		seen[s] = true
		if !local[s] {
			drift = append(drift, s+": in calibrate.Classes() but not in testapps classes")
		}
	}
	for c := range local {
		if !seen[c] {
			drift = append(drift, c+": in testapps classes but not in calibrate.Classes()")
		}
	}
	slices.Sort(drift)
	return drift
}
