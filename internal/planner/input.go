package planner

import (
	"errors"
	"fmt"
)

// RouteID and SinkID are the static graph's IDs. The caller copies them
// from static.Graph, since planner may not import static.
type (
	RouteID uint32
	SinkID  uint32
)

// Methods is a set of HTTP methods with the same bits as static.Methods.
type Methods uint16

// HTTP methods. MethodOther stands for a method list that is not literal or
// names a method outside this set.
const (
	MethodGet Methods = 1 << iota
	MethodPost
	MethodPut
	MethodPatch
	MethodDelete
	MethodHead
	MethodOptions
	MethodTrace
	MethodOther
)

const (
	allMethods = MethodOther<<1 - 1
	// writeMethods change state on the server; they rank above read-only
	// routes when every other fact ties.
	writeMethods = MethodPost | MethodPut | MethodPatch | MethodDelete | MethodOther
)

// SinkKind is the class of a dangerous call, with the same values as
// static.SinkKind. The zero value is not a kind.
type SinkKind uint8

// Sink kinds.
const (
	SinkSQL SinkKind = iota + 1
	SinkShell
	SinkFile
	SinkHTTPClient
	SinkTemplate
)

// Tier is the calibration tier (calibrate.Tier S, M or L). The zero value
// is not a tier: the caller maps an unmeasured model to TierS, as
// calibrate does.
type Tier uint8

// Tiers.
const (
	TierS Tier = iota + 1
	TierM
	TierL
)

// Input is everything the planner sees. It holds only IDs, enums, booleans
// and token counts, so no text from the scanned repository can reach the
// planner (invariant 3); text_test.go fails if a type that can carry text
// becomes reachable from it.
type Input struct {
	Tier   Tier
	Budget Budget
	Routes []Route
	Sinks  []Sink
}

// Budget is what the run may spend on reader calls.
type Budget struct {
	// Tokens is what is left of the run's model budget.
	Tokens uint32
	// StepTokens is the most one reader call can spend at this tier
	// (system prompt, slice and reply). Every planned hypothesis reserves
	// it in full, so the plan never needs more than Tokens.
	StepTokens uint32
}

// Route is one HTTP endpoint.
type Route struct {
	ID      RouteID
	Methods Methods
	// Authenticated is set when static saw an auth decorator, dependency
	// or call on the route. It is a name-based hint, not proof.
	Authenticated bool
}

// Sink is a dangerous call reachable from a route's handler.
type Sink struct {
	ID            SinkID
	Route         RouteID
	Kind          SinkKind
	DynamicArg    bool // the first argument is not built only from literals
	Parameterized bool // a SQL call passes bound parameters; ignored on other kinds
	Indirect      bool // the call sits in a helper the handler calls
}

// ErrInput means the input breaks the contract: an unknown enum value, a
// duplicate or dangling ID, a zero step cost or too many entries. Messages
// hold only numbers.
var ErrInput = errors.New("planner: invalid input")

// maxEntries caps routes and sinks so the work per run stays bounded
// (sorting is O(n log n) on at most this many sinks).
const maxEntries = 1 << 20

func (in Input) validate() (map[RouteID]Route, error) {
	if _, ok := strategyFor(in.Tier); !ok {
		return nil, fmt.Errorf("%w: tier %d", ErrInput, in.Tier)
	}
	if in.Budget.StepTokens == 0 {
		return nil, fmt.Errorf("%w: zero step tokens", ErrInput)
	}
	if len(in.Routes) > maxEntries || len(in.Sinks) > maxEntries {
		return nil, fmt.Errorf("%w: %d routes and %d sinks, cap %d", ErrInput, len(in.Routes), len(in.Sinks), maxEntries)
	}
	routes, err := indexRoutes(in.Routes)
	if err != nil {
		return nil, err
	}
	return routes, checkSinks(in.Sinks, routes)
}

func indexRoutes(list []Route) (map[RouteID]Route, error) {
	routes := make(map[RouteID]Route, len(list))
	for _, r := range list {
		if _, dup := routes[r.ID]; dup {
			return nil, fmt.Errorf("%w: duplicate route %d", ErrInput, r.ID)
		}
		if r.Methods&^allMethods != 0 {
			return nil, fmt.Errorf("%w: route %d has method bits %#x", ErrInput, r.ID, uint16(r.Methods))
		}
		routes[r.ID] = r
	}
	return routes, nil
}

func checkSinks(list []Sink, routes map[RouteID]Route) error {
	seen := make(map[SinkID]bool, len(list))
	for _, s := range list {
		if seen[s.ID] {
			return fmt.Errorf("%w: duplicate sink %d", ErrInput, s.ID)
		}
		seen[s.ID] = true
		if _, ok := routes[s.Route]; !ok {
			return fmt.Errorf("%w: sink %d names unknown route %d", ErrInput, s.ID, s.Route)
		}
		if s.Kind < SinkSQL || s.Kind > SinkTemplate {
			return fmt.Errorf("%w: sink %d has kind %d", ErrInput, s.ID, s.Kind)
		}
	}
	return nil
}
