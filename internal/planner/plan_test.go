package planner

import (
	"slices"
	"testing"
)

const step = 100 // StepTokens in these tests

// route IDs used by the tables: 1 is open, 2 needs auth, 3 is open GET only.
var testRoutes = []Route{
	{ID: 1, Methods: MethodPost},
	{ID: 2, Methods: MethodPost, Authenticated: true},
	{ID: 3, Methods: MethodGet},
}

// dyn is a sink whose argument can carry input on route 1.
func dyn(id SinkID, k SinkKind) Sink { return Sink{ID: id, Route: 1, Kind: k, DynamicArg: true} }

func input(tier Tier, steps uint32, sinks ...Sink) Input {
	return Input{Tier: tier, Budget: Budget{Tokens: steps * step, StepTokens: step}, Routes: testRoutes, Sinks: sinks}
}

func planned(p Plan) []SinkID {
	ids := []SinkID{}
	for _, h := range p.Hypotheses {
		ids = append(ids, h.Sink)
	}
	return ids
}

func TestBuildPrioritizes(t *testing.T) {
	authed, getOnly := dyn(0, SinkSQL), dyn(0, SinkSQL)
	authed.Route, getOnly.Route = 2, 3
	tests := []struct {
		name  string
		sinks []Sink
		want  []SinkID // planned order
	}{
		{"unauth above auth", []Sink{with(authed, 1), dyn(2, SinkSQL)}, []SinkID{2, 1}},
		{"unauth file above auth shell", []Sink{with(Sink{Route: 2, Kind: SinkShell, DynamicArg: true}, 1), dyn(2, SinkFile)}, []SinkID{2, 1}},
		{"unauth parameterized above auth unparameterized", []Sink{with(authed, 1), {ID: 2, Route: 1, Kind: SinkSQL, DynamicArg: true, Parameterized: true}}, []SinkID{2, 1}},
		{"dynamic above literal even with auth", []Sink{{ID: 1, Route: 1, Kind: SinkShell}, with(authed, 2)}, []SinkID{2, 1}},
		{"unparameterized above parameterized", []Sink{{ID: 1, Route: 1, Kind: SinkSQL, DynamicArg: true, Parameterized: true}, dyn(2, SinkSQL)}, []SinkID{2, 1}},
		{"severity", []Sink{dyn(1, SinkHTTPClient), dyn(2, SinkFile), dyn(3, SinkTemplate), dyn(4, SinkSQL), dyn(5, SinkShell)}, []SinkID{5, 4, 3, 2, 1}},
		{"direct above indirect", []Sink{{ID: 1, Route: 1, Kind: SinkSQL, DynamicArg: true, Indirect: true}, dyn(2, SinkSQL)}, []SinkID{2, 1}},
		{"write method above GET", []Sink{with(getOnly, 1), dyn(2, SinkSQL)}, []SinkID{2, 1}},
		{"ties go to the lower sink ID", []Sink{dyn(9, SinkSQL), dyn(3, SinkSQL), dyn(7, SinkSQL)}, []SinkID{3, 7, 9}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := mustBuild(t, input(TierM, 100, tt.sinks...))
			if got := planned(p); !slices.Equal(got, tt.want) {
				t.Errorf("planned %v, want %v", got, tt.want)
			}
			// The same facts in reverse input order give the same plan.
			rev := slices.Clone(tt.sinks)
			slices.Reverse(rev)
			if got := planned(mustBuild(t, input(TierM, 100, rev...))); !slices.Equal(got, tt.want) {
				t.Errorf("reversed input planned %v, want %v", got, tt.want)
			}
		})
	}
}

func with(s Sink, id SinkID) Sink {
	s.ID = id
	return s
}

func TestBuildRespectsBudgetAndTier(t *testing.T) {
	many := func(n int) []Sink {
		var s []Sink
		for i := range n {
			s = append(s, dyn(SinkID(i+1), SinkSQL)) //nolint:gosec // G115: small test counts
		}
		return s
	}
	literal := Sink{ID: 50, Route: 1, Kind: SinkShell}
	tests := []struct {
		name     string
		in       Input
		planned  int
		skipped  map[SkipReason]int
		lastSkip SinkID
	}{
		{name: "zero budget", in: input(TierL, 0, many(3)...), skipped: map[SkipReason]int{SkipBudget: 3}},
		{name: "budget below one step", in: Input{Tier: TierL, Budget: Budget{Tokens: step - 1, StepTokens: step}, Routes: testRoutes, Sinks: many(2)}, skipped: map[SkipReason]int{SkipBudget: 2}},
		{name: "budget for two", in: input(TierM, 2, many(5)...), planned: 2, skipped: map[SkipReason]int{SkipBudget: 3}},
		{name: "budget with a remainder", in: Input{Tier: TierM, Budget: Budget{Tokens: 3*step - 1, StepTokens: step}, Routes: testRoutes, Sinks: many(5)}, planned: 2, skipped: map[SkipReason]int{SkipBudget: 3}},
		{name: "no sinks", in: input(TierS, 10)},
		{name: "tier S step bound", in: input(TierS, 1000, many(40)...), planned: 32, skipped: map[SkipReason]int{SkipStepCap: 8}},
		{name: "tier S skips literal arguments", in: input(TierS, 1000, append(many(2), literal)...), planned: 2, skipped: map[SkipReason]int{SkipLowRisk: 1}},
		{name: "tier S low risk skipped even when budget is spent", in: input(TierS, 1, append(many(2), literal)...), planned: 1, skipped: map[SkipReason]int{SkipBudget: 1, SkipLowRisk: 1}, lastSkip: 50},
		{name: "tier M plans literal arguments last", in: input(TierM, 1000, append(many(2), literal)...), planned: 3},
		{name: "tier M step bound", in: input(TierM, 1000, many(300)...), planned: 256, skipped: map[SkipReason]int{SkipStepCap: 44}},
		{name: "tier L step bound", in: input(TierL, 5000, many(1100)...), planned: 1024, skipped: map[SkipReason]int{SkipStepCap: 76}},
		{name: "budget binds before the step bound", in: input(TierL, 10, many(20)...), planned: 10, skipped: map[SkipReason]int{SkipBudget: 10}},
		{name: "budget equal to the step bound", in: input(TierS, 32, many(33)...), planned: 32, skipped: map[SkipReason]int{SkipStepCap: 1}},
		{name: "maximum budget", in: Input{Tier: TierS, Budget: Budget{Tokens: 1<<32 - 1, StepTokens: 1}, Routes: testRoutes, Sinks: many(2)}, planned: 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := mustBuild(t, tt.in)
			if len(p.Hypotheses) != tt.planned {
				t.Errorf("planned %d, want %d", len(p.Hypotheses), tt.planned)
			}
			if got := reasons(p); !mapsEqual(got, tt.skipped) {
				t.Errorf("skipped %v, want %v", got, tt.skipped)
			}
			if spent := uint64(len(p.Hypotheses)) * uint64(tt.in.Budget.StepTokens); spent > uint64(tt.in.Budget.Tokens) {
				t.Errorf("plan needs %d tokens, budget is %d", spent, tt.in.Budget.Tokens)
			}
			if tt.lastSkip != 0 && p.Skipped[len(p.Skipped)-1].Sink != tt.lastSkip {
				t.Errorf("last skipped %d, want %d", p.Skipped[len(p.Skipped)-1].Sink, tt.lastSkip)
			}
			checkPlan(t, tt.in, p)
		})
	}
}

func reasons(p Plan) map[SkipReason]int {
	got := map[SkipReason]int{}
	for _, s := range p.Skipped {
		got[s.Reason]++
	}
	return got
}

func mapsEqual(a, b map[SkipReason]int) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// checkPlan holds for every plan: each input sink appears once, IDs are
// 1-based positions, risk never rises down the list, and every field is a
// known enum value that matches the input.
func checkPlan(t *testing.T, in Input, p Plan) {
	t.Helper()
	sinks := map[SinkID]Sink{}
	for _, s := range in.Sinks {
		sinks[s.ID] = s
	}
	seen := map[SinkID]bool{}
	for i, h := range p.Hypotheses {
		s, ok := sinks[h.Sink]
		if !ok || seen[h.Sink] || h.ID != HypothesisID(i+1) || h.Route != s.Route || h.Class != classOf(s.Kind) || h.Risk < RiskLow || h.Risk > RiskHigh { //nolint:gosec // G115: small test counts
			t.Fatalf("hypothesis %d = %+v does not match input sink %+v", i, h, s)
		}
		if i > 0 && h.Risk > p.Hypotheses[i-1].Risk {
			t.Fatalf("hypothesis %d has risk %d above the one before it", i, h.Risk)
		}
		seen[h.Sink] = true
	}
	for _, s := range p.Skipped {
		if _, ok := sinks[s.Sink]; !ok || seen[s.Sink] || s.Reason < SkipLowRisk || s.Reason > SkipBudget {
			t.Fatalf("skipped %+v is unknown, repeated or has no reason", s)
		}
		seen[s.Sink] = true
	}
	if len(seen) != len(sinks) {
		t.Fatalf("plan covers %d of %d sinks", len(seen), len(sinks))
	}
}

func TestRiskAndClass(t *testing.T) {
	tests := []struct {
		sink  Sink
		route Route
		risk  Risk
		class Class
	}{
		{Sink{Kind: SinkShell, DynamicArg: true}, Route{}, RiskHigh, ClassCommandInjection},
		{Sink{Kind: SinkSQL, DynamicArg: true}, Route{Authenticated: true}, RiskMedium, ClassSQLInjection},
		{Sink{Kind: SinkSQL, DynamicArg: true, Parameterized: true}, Route{}, RiskMedium, ClassSQLInjection},
		{Sink{Kind: SinkFile}, Route{}, RiskLow, ClassPathTraversal},
		{Sink{Kind: SinkHTTPClient, Parameterized: true}, Route{Authenticated: true}, RiskLow, ClassSSRF},
		{Sink{Kind: SinkTemplate, DynamicArg: true, Indirect: true}, Route{}, RiskHigh, ClassTemplateInjection},
	}
	for _, tt := range tests {
		if got := riskOf(tt.sink, tt.route); got != tt.risk {
			t.Errorf("riskOf(%+v, %+v) = %d, want %d", tt.sink, tt.route, got, tt.risk)
		}
		if got := classOf(tt.sink.Kind); got != tt.class {
			t.Errorf("classOf(%d) = %d, want %d", tt.sink.Kind, got, tt.class)
		}
	}
}

func mustBuild(t *testing.T, in Input) Plan {
	t.Helper()
	p, err := Build(in)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return p
}

// BenchmarkBuild backs the O(n log n) worst case in doc.go at 2^16 sinks.
func BenchmarkBuild(b *testing.B) {
	const n = 1 << 16
	in := Input{Tier: TierL, Budget: Budget{Tokens: 1 << 31, StepTokens: 1}}
	for i := range n {
		id := uint32(i) //nolint:gosec // G115: i < n
		in.Routes = append(in.Routes, Route{ID: RouteID(id), Methods: Methods(id) & allMethods, Authenticated: i%3 == 0})
		in.Sinks = append(in.Sinks, Sink{ID: SinkID(n - id), Route: RouteID(id), Kind: SinkKind(i%5 + 1), DynamicArg: i%2 == 0, Parameterized: i%7 == 0})
	}
	for b.Loop() {
		if _, err := Build(in); err != nil {
			b.Fatal(err)
		}
	}
}
