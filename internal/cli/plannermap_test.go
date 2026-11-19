package cli

import (
	"errors"
	"math"
	"testing"

	"github.com/sneakercreepers/creep/internal/calibrate"
	"github.com/sneakercreepers/creep/internal/discover"
	"github.com/sneakercreepers/creep/internal/planner"
	"github.com/sneakercreepers/creep/internal/reader"
)

// probeKind reports whether the planner accepts a sink of kind k.
func probeKind(k planner.SinkKind) bool {
	_, err := planner.Build(planner.Input{
		Tier: planner.TierL, Budget: planner.Budget{Tokens: 1 << 20, StepTokens: 1},
		Routes: []planner.Route{{ID: 0, Methods: planner.MethodGet}},
		Sinks:  []planner.Sink{{ID: 0, Route: 0, Kind: k, DynamicArg: true}},
	})
	return err == nil
}

// Every discover.SinkKind (those with a name) maps to a planner kind, every
// kind the planner accepts is the image of one, and an unknown kind fails
// closed. A kind added on either side fails here until it is mapped or
// named in pendingKinds (#201 added static.SinkNoSQL; #212 mapped it).
func TestSinkKindMappingIsExhaustive(t *testing.T) {
	mapped := map[planner.SinkKind]bool{}
	for k := discover.SinkKind(1); k != 0; k++ {
		got, err := plannerKind(k)
		if k.String() == "unknown" {
			if !errors.Is(err, errUnmapped) {
				t.Errorf("unknown discover kind %d mapped to %d", k, got)
			}
			continue
		}
		if issue, pending := pendingKinds[k]; pending {
			if !errors.Is(err, errUnmapped) || readClasses[kindClass(k)] {
				t.Errorf("discover kind %s is pending (%s) but maps to %d; remove it from pendingKinds", k, issue, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("discover kind %s has no planner mapping (or add it to pendingKinds with its issue)", k)
			continue
		}
		if mapped[got] {
			t.Errorf("discover kind %s maps to planner kind %d twice", k, got)
		}
		mapped[got] = true
		if kindClass(k) == k.String() || !readClasses[kindClass(k)] {
			t.Errorf("discover kind %s has no report class", k)
		}
	}
	for k := planner.SinkKind(1); k != 0; k++ {
		if probeKind(k) && !mapped[k] {
			t.Errorf("planner kind %d is accepted but no discover kind maps to it", k)
		}
	}
}

// Every named discover method bit maps explicitly; every bit the planner
// accepts is reached; an unknown bit becomes MethodOther, never dropped.
func TestMethodMappingIsExhaustive(t *testing.T) {
	var reached planner.Methods
	for i := range 16 {
		bit := discover.Methods(1) << i
		got, ok := plannerMethod(bit)
		if bit&discover.AllMethods == 0 {
			if ok || plannerMethods(bit) != planner.MethodOther {
				t.Errorf("unnamed bit %#x mapped to %#x", uint16(bit), uint16(got))
			}
			continue
		}
		if !ok || got == 0 || got&(got-1) != 0 {
			t.Errorf("method %#x maps to %#x, want one planner bit", uint16(bit), uint16(got))
		}
		reached |= got
	}
	for i := range 16 {
		bit := planner.Methods(1) << i
		_, err := planner.Build(planner.Input{
			Tier: planner.TierL, Budget: planner.Budget{Tokens: 1, StepTokens: 1},
			Routes: []planner.Route{{ID: 0, Methods: bit}},
		})
		if err == nil && reached&bit == 0 {
			t.Errorf("planner method bit %#x is accepted but nothing maps to it", uint16(bit))
		}
	}
}

// Every calibrate tier maps to a planner and a reader tier, and every
// planner tier is reached; an unknown tier fails closed.
func TestTierMappingIsExhaustive(t *testing.T) {
	reached := map[planner.Tier]bool{}
	for _, tier := range []calibrate.Tier{calibrate.TierS, calibrate.TierM, calibrate.TierL} {
		p, err := plannerTier(tier)
		if err != nil {
			t.Fatalf("tier %s: %v", tier, err)
		}
		r, err := readerTier(tier)
		if err != nil || string(r) != string(tier) {
			t.Fatalf("reader tier %s = %q, %v", tier, r, err)
		}
		reached[p] = true
	}
	for _, bad := range []calibrate.Tier{"", "XL", "s"} {
		if _, err := plannerTier(bad); !errors.Is(err, errUnmapped) {
			t.Errorf("planner tier %q: %v", bad, err)
		}
		if _, err := readerTier(bad); !errors.Is(err, errUnmapped) {
			t.Errorf("reader tier %q: %v", bad, err)
		}
	}
	for tier := planner.Tier(1); tier != 0; tier++ {
		_, err := planner.Build(planner.Input{Tier: tier, Budget: planner.Budget{Tokens: 1, StepTokens: 1}})
		if err == nil && !reached[tier] {
			t.Errorf("planner tier %d is accepted but no calibrate tier maps to it", tier)
		}
	}
}

// Every class the planner emits maps to a reader class, every reader class
// is reached, and the reader class matches the report class of the sink
// kind it came from.
func TestClassMappingIsExhaustive(t *testing.T) {
	reached := map[reader.Class]bool{}
	for k := discover.SinkKind(1); k != 0; k++ {
		pk, err := plannerKind(k)
		if err != nil {
			continue
		}
		plan, err := planner.Build(planner.Input{
			Tier: planner.TierL, Budget: planner.Budget{Tokens: math.MaxUint32, StepTokens: 1},
			Routes: []planner.Route{{ID: 0, Methods: planner.MethodGet}},
			Sinks:  []planner.Sink{{ID: 0, Route: 0, Kind: pk, DynamicArg: true}},
		})
		if err != nil || len(plan.Hypotheses) != 1 {
			t.Fatalf("kind %s: plan %+v, %v", k, plan, err)
		}
		rc, err := readerClass(plan.Hypotheses[0].Class)
		if err != nil {
			t.Fatalf("planner class %d: %v", plan.Hypotheses[0].Class, err)
		}
		if want := kindClass(k); readerReportName(rc) != want {
			t.Errorf("kind %s: reader class %s, report class %s", k, rc, want)
		}
		reached[rc] = true
	}
	for c := reader.Class(1); c != 0; c++ {
		if c.String() != "unknown" && !reached[c] {
			t.Errorf("reader class %s is never reached", c)
		}
	}
	if _, err := readerClass(0); !errors.Is(err, errUnmapped) {
		t.Errorf("planner class 0: %v", err)
	}
}

// readerReportName is the report class of a reader class, for the check
// above; the reader says sql_injection where calibration says sqli.
func readerReportName(c reader.Class) string {
	if c == reader.ClassSQLInjection {
		return string(calibrate.ClassSQLi)
	}
	return c.String()
}

