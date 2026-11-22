package recipe

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/sneakercreepers/creep/internal/reader"
)

var tiers = []reader.Tier{reader.TierS, reader.TierM, reader.TierL}

// TestFailingFixturesRefused is acceptance criterion 1 of #33: a recipe
// loads only when the model flags its vulnerable fixture and clears its
// safe one, each on a whole slice; anything else refuses it, and a model
// failure is an error, never a verdict.
func TestFailingFixturesRefused(t *testing.T) {
	long := templateRecipe(t)
	// A sink line longer than the S tier shows is cut, so its slice is partial.
	long.Fixtures.Safe.Code = strings.Replace(long.Fixtures.Safe.Code, "(name,))", "(name,))  # "+strings.Repeat("x", 300), 1)
	model := errors.New("endpoint down")
	tests := []struct {
		name    string
		data    []byte
		verdict map[int]string
		fail    error
		want    error // nil: loads
		calls   int
	}{
		{"both right", Template(), map[int]string{9: "vulnerable"}, nil, nil, 2},
		{"vulnerable not flagged", Template(), map[int]string{}, nil, ErrFixtures, 2},
		{"vulnerable inconclusive", Template(), map[int]string{9: "inconclusive"}, nil, ErrFixtures, 2},
		{"safe flagged", Template(), map[int]string{9: "vulnerable", 8: "vulnerable"}, nil, ErrFixtures, 2},
		{"safe inconclusive", Template(), map[int]string{9: "vulnerable", 8: "inconclusive"}, nil, ErrFixtures, 2},
		{"swapped", Template(), map[int]string{8: "vulnerable"}, nil, ErrFixtures, 2},
		{"safe read on a cut slice", encode(t, long), map[int]string{9: "vulnerable"}, nil, ErrFixtures, 2},
		{"model fails", Template(), nil, model, model, 1},
		{"invalid recipe calls no model", []byte(`{"version":1}`), nil, nil, ErrInvalid, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tier := reader.TierM
			if tt.name == "safe read on a cut slice" {
				tier = reader.TierS
			}
			m := &fakeModel{verdict: tt.verdict, fail: tt.fail}
			r, _, err := checker(t, m, tier).Load(context.Background(), tt.data, acceptPoC)
			if tt.want == nil && (err != nil || r == nil) {
				t.Fatalf("Load = %v, %v; want the recipe", r, err)
			}
			if tt.want != nil && (!errors.Is(err, tt.want) || r != nil) {
				t.Fatalf("Load = %v, %v; want %v and no recipe", r, err, tt.want)
			}
			if tt.want != nil && tt.want != ErrInvalid && errors.Is(err, ErrInvalid) {
				t.Errorf("a fixture failure reads as a format error: %v", err)
			}
			if len(m.calls) != tt.calls {
				t.Errorf("%d model calls, want %d", len(m.calls), tt.calls)
			}
		})
	}
}

// Every tier loads the template with a model that gets it right, so the
// fixtures fit each tier's slice whole.
func TestTemplateLoadsAtEveryTier(t *testing.T) {
	for _, tier := range tiers {
		if _, out, err := checker(t, rightModel(), tier).Load(context.Background(), Template(), acceptPoC); err != nil || out.Vulnerable.Partial || out.Safe.Partial {
			t.Errorf("tier %s: %v, %+v", tier, err, out)
		}
	}
}

// A Checker without its model or redactor fails before any call.
func TestCheckerNeedsItsParts(t *testing.T) {
	r, err := Parse(Template(), acceptPoC)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []Checker{{}, {Model: checker(t, rightModel(), reader.TierM).Model}} {
		if _, err := c.Check(context.Background(), r); err == nil {
			t.Errorf("Check with %+v succeeded", c)
		}
	}
	if _, err := checker(t, rightModel(), reader.Tier("XL")).Check(context.Background(), r); !errors.Is(err, reader.ErrTier) {
		t.Errorf("unknown tier: %v, want reader.ErrTier", err)
	}
}
