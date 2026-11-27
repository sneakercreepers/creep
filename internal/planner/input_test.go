package planner

import (
	"errors"
	"testing"
)

func TestBuildRejectsBadInput(t *testing.T) {
	ok := input(TierS, 10, dyn(1, SinkSQL))
	edit := func(f func(*Input)) Input {
		in := ok
		in.Routes = append([]Route(nil), ok.Routes...)
		in.Sinks = append([]Sink(nil), ok.Sinks...)
		f(&in)
		return in
	}
	tests := []struct {
		name string
		in   Input
	}{
		{"zero tier", edit(func(in *Input) { in.Tier = 0 })},
		{"unknown tier", edit(func(in *Input) { in.Tier = TierL + 1 })},
		{"zero step tokens", edit(func(in *Input) { in.Budget.StepTokens = 0 })},
		{"zero step tokens and zero budget", edit(func(in *Input) { in.Budget = Budget{} })},
		{"duplicate route", edit(func(in *Input) { in.Routes = append(in.Routes, Route{ID: 1}) })},
		{"unknown method bit", edit(func(in *Input) { in.Routes[0].Methods = MethodOther << 1 })},
		{"duplicate sink", edit(func(in *Input) { in.Sinks = append(in.Sinks, dyn(1, SinkShell)) })},
		{"dangling route", edit(func(in *Input) { in.Sinks[0].Route = 99 })},
		{"zero sink kind", edit(func(in *Input) { in.Sinks[0].Kind = 0 })},
		{"unknown sink kind", edit(func(in *Input) { in.Sinks[0].Kind = lastSinkKind + 1 })},
		{"too many sinks", edit(func(in *Input) { in.Sinks = make([]Sink, maxEntries+1) })},
		{"too many routes", edit(func(in *Input) { in.Routes = make([]Route, maxEntries+1) })},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := Build(tt.in)
			if !errors.Is(err, ErrInput) {
				t.Fatalf("err = %v, want ErrInput", err)
			}
			if len(p.Hypotheses) != 0 || len(p.Skipped) != 0 {
				t.Errorf("failed Build returned a plan %+v", p)
			}
		})
	}
	if _, err := Build(ok); err != nil {
		t.Fatalf("valid input rejected: %v", err)
	}
}

// TestBuildAcceptsEveryKnownValue guards against a validation that is too
// strict: each enum value and the full method set pass.
func TestBuildAcceptsEveryKnownValue(t *testing.T) {
	for _, tier := range []Tier{TierS, TierM, TierL} {
		in := Input{Tier: tier, Budget: Budget{Tokens: 1, StepTokens: 1}, Routes: []Route{{ID: 0, Methods: allMethods}}}
		for k := SinkSQL; k <= lastSinkKind; k++ {
			in.Sinks = append(in.Sinks, Sink{ID: SinkID(k), Route: 0, Kind: k, DynamicArg: true})
		}
		p := mustBuild(t, in)
		checkPlan(t, in, p)
	}
}
