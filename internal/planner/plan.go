package planner

import (
	"cmp"
	"slices"
)

// HypothesisID names one planned hypothesis. It is the hypothesis's
// 1-based position in Plan.Hypotheses and is what reader.HypothesisID echoes.
type HypothesisID uint32

// Class is the vulnerability class a hypothesis names, with the same values
// as reader.Class. The zero value is not a class.
type Class uint8

// Classes.
const (
	ClassSQLInjection Class = iota + 1
	ClassCommandInjection
	ClassPathTraversal
	ClassSSRF
	ClassTemplateInjection
)

// Risk is how likely a hypothesis is to hold and be reachable, from static
// facts alone. The zero value is not a risk.
type Risk uint8

// Risks, lowest first.
const (
	// RiskLow: the argument is built only from literals.
	RiskLow Risk = iota + 1
	// RiskMedium: the argument can carry input, but the route needs auth
	// or the SQL call binds parameters.
	RiskMedium
	// RiskHigh: the argument can carry input on a route with no auth seen
	// and no bound parameters.
	RiskHigh
)

// SkipReason says why a sink got no hypothesis. The zero value is not a
// reason.
type SkipReason uint8

// Skip reasons.
const (
	// SkipLowRisk: the tier's strategy does not spend steps on RiskLow.
	SkipLowRisk SkipReason = iota + 1
	// SkipStepCap: the tier's step bound was reached.
	SkipStepCap
	// SkipBudget: the token budget was spent.
	SkipBudget
)

// Plan is the planner's output, a closed schema of IDs and enums with no
// free-text field; text_test.go fails if that changes. Every input sink
// appears exactly once, in Hypotheses or in Skipped, so the report can list
// every skipped sink as not evaluated.
type Plan struct {
	Hypotheses []Hypothesis // highest risk first; one reader step each
	Skipped    []Skipped    // in the same priority order
}

// Hypothesis is one route→sink question for the reader.
type Hypothesis struct {
	ID    HypothesisID
	Route RouteID
	Sink  SinkID
	Class Class
	Risk  Risk
}

// Skipped is a sink the plan leaves out, and why.
type Skipped struct {
	Sink   SinkID
	Reason SkipReason
}

// strategy is how a tier spends reader steps.
type strategy struct {
	maxSteps uint32 // hypotheses per run, whatever the budget
	minRisk  Risk   // lower risks are skipped
}

// strategyFor bounds tier S hardest: a small model gets few steps and none
// on sinks whose argument is a literal, where its verdicts are mostly noise.
func strategyFor(t Tier) (strategy, bool) {
	switch t {
	case TierS:
		return strategy{maxSteps: 32, minRisk: RiskMedium}, true
	case TierM:
		return strategy{maxSteps: 256, minRisk: RiskLow}, true
	case TierL:
		return strategy{maxSteps: 1024, minRisk: RiskLow}, true
	}
	return strategy{}, false
}

// candidate is a sink with the route facts the ranking needs.
type candidate struct {
	sink  Sink
	route Route
	risk  Risk
}

// Build ranks every sink by risk and plans hypotheses for the highest
// ones, within the tier's step bound and the token budget. It fails with
// ErrInput when the input breaks the contract.
func Build(in Input) (Plan, error) {
	routes, err := in.validate()
	if err != nil {
		return Plan{}, err
	}
	st, _ := strategyFor(in.Tier) // validate checked the tier
	return assign(rank(in.Sinks, routes), st, in.Budget), nil
}

func rank(sinks []Sink, routes map[RouteID]Route) []candidate {
	ranked := make([]candidate, 0, len(sinks))
	for _, s := range sinks {
		r := routes[s.Route]
		ranked = append(ranked, candidate{sink: s, route: r, risk: riskOf(s, r)})
	}
	slices.SortFunc(ranked, compareRisk)
	return ranked
}

func riskOf(s Sink, r Route) Risk {
	switch {
	case !s.DynamicArg:
		return RiskLow
	case !s.Parameterized && !r.Authenticated:
		return RiskHigh
	}
	return RiskMedium
}

// compareRisk orders a before b when a is riskier: risk, then no auth,
// then no bound parameters, then sink severity, then a direct call, then a
// state-changing method. Sink IDs are unique, so the last key makes the
// order total and the plan deterministic.
func compareRisk(a, b candidate) int {
	return cmp.Or(
		cmp.Compare(b.risk, a.risk),
		cmp.Compare(btoi(!b.route.Authenticated), btoi(!a.route.Authenticated)),
		cmp.Compare(btoi(!b.sink.Parameterized), btoi(!a.sink.Parameterized)),
		cmp.Compare(severity(b.sink.Kind), severity(a.sink.Kind)),
		cmp.Compare(btoi(!b.sink.Indirect), btoi(!a.sink.Indirect)),
		cmp.Compare(btoi(b.route.Methods&writeMethods != 0), btoi(a.route.Methods&writeMethods != 0)),
		cmp.Compare(a.sink.ID, b.sink.ID),
	)
}

// severity ranks what a sink lets an attacker do: run commands, read or
// change the database, run template code, touch files, then reach other
// hosts.
func severity(k SinkKind) int {
	switch k {
	case SinkShell:
		return 5
	case SinkSQL:
		return 4
	case SinkTemplate:
		return 3
	case SinkFile:
		return 2
	}
	return 1
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

// assign walks the ranking and plans each eligible sink until the step
// bound or the budget runs out; the rest are skipped with the reason.
func assign(ranked []candidate, st strategy, b Budget) Plan {
	affordable := b.Tokens / b.StepTokens
	steps, full := min(affordable, st.maxSteps), SkipBudget
	if affordable >= st.maxSteps {
		full = SkipStepCap
	}
	var p Plan
	for _, c := range ranked {
		switch {
		case c.risk < st.minRisk:
			p.Skipped = append(p.Skipped, Skipped{Sink: c.sink.ID, Reason: SkipLowRisk})
		case uint32(len(p.Hypotheses)) >= steps: //nolint:gosec // G115: len is at most maxEntries
			p.Skipped = append(p.Skipped, Skipped{Sink: c.sink.ID, Reason: full})
		default:
			p.Hypotheses = append(p.Hypotheses, hypothesis(c, len(p.Hypotheses)+1))
		}
	}
	return p
}

func hypothesis(c candidate, position int) Hypothesis {
	return Hypothesis{
		ID:    HypothesisID(position), //nolint:gosec // G115: position is at most maxEntries
		Route: c.route.ID,
		Sink:  c.sink.ID,
		Class: classOf(c.sink.Kind),
		Risk:  c.risk,
	}
}

// classOf maps a validated sink kind to the class the reader checks.
func classOf(k SinkKind) Class {
	switch k {
	case SinkSQL:
		return ClassSQLInjection
	case SinkShell:
		return ClassCommandInjection
	case SinkFile:
		return ClassPathTraversal
	case SinkHTTPClient:
		return ClassSSRF
	}
	return ClassTemplateInjection
}
