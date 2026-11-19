package cli

import (
	"errors"
	"fmt"

	"github.com/sneakercreepers/creep/internal/calibrate"
	"github.com/sneakercreepers/creep/internal/discover"
	"github.com/sneakercreepers/creep/internal/planner"
	"github.com/sneakercreepers/creep/internal/reader"
)

// The planner may not import discover, calibrate or reader (invariant 3 and
// the layer table), and its enums repeat their numeric values. A numeric
// cast would pass a value added on one side straight through, so each value
// is mapped by an explicit switch; plannermap_test.go fails when either side
// gains a value this file does not name.

// errUnmapped means a value has no mapping here; the scan fails closed.
var errUnmapped = errors.New("no planner mapping")

// pendingKinds are discover sink kinds the planner and reader cannot take yet,
// with the issue that adds them. Their sinks are listed as not evaluated
// (unmapped_kind) and the run is incomplete. plannermap_test.go fails if one
// gets a mapping without leaving this list, or if any other kind is unmapped.
// It is empty since #212 mapped SinkNoSQL.
var pendingKinds = map[discover.SinkKind]string{}

// plannerKind maps a discover sink kind. An unmapped kind (a new discover kind
// before the planner learns it) is listed as not evaluated, never planned.
func plannerKind(k discover.SinkKind) (planner.SinkKind, error) {
	switch k {
	case discover.SinkSQL:
		return planner.SinkSQL, nil
	case discover.SinkShell:
		return planner.SinkShell, nil
	case discover.SinkFile:
		return planner.SinkFile, nil
	case discover.SinkHTTPClient:
		return planner.SinkHTTPClient, nil
	case discover.SinkTemplate:
		return planner.SinkTemplate, nil
	case discover.SinkNoSQL:
		return planner.SinkNoSQL, nil
	}
	return 0, fmt.Errorf("sink kind %d: %w", k, errUnmapped)
}

// plannerMethods maps each method bit. An unknown bit becomes MethodOther,
// which the planner ranks as state-changing: the safe direction.
func plannerMethods(m discover.Methods) planner.Methods {
	var out planner.Methods
	for bit := discover.Methods(1); bit != 0; bit <<= 1 {
		if m&bit == 0 {
			continue
		}
		p, ok := plannerMethod(bit)
		if !ok {
			p = planner.MethodOther
		}
		out |= p
	}
	return out
}

func plannerMethod(bit discover.Methods) (planner.Methods, bool) {
	switch bit {
	case discover.MethodGet:
		return planner.MethodGet, true
	case discover.MethodPost:
		return planner.MethodPost, true
	case discover.MethodPut:
		return planner.MethodPut, true
	case discover.MethodPatch:
		return planner.MethodPatch, true
	case discover.MethodDelete:
		return planner.MethodDelete, true
	case discover.MethodHead:
		return planner.MethodHead, true
	case discover.MethodOptions:
		return planner.MethodOptions, true
	case discover.MethodTrace:
		return planner.MethodTrace, true
	case discover.MethodOther:
		return planner.MethodOther, true
	}
	return 0, false
}

// plannerTier maps the calibrated tier.
func plannerTier(t calibrate.Tier) (planner.Tier, error) {
	switch t {
	case calibrate.TierS:
		return planner.TierS, nil
	case calibrate.TierM:
		return planner.TierM, nil
	case calibrate.TierL:
		return planner.TierL, nil
	}
	return 0, fmt.Errorf("tier %q: %w", string(t), errUnmapped)
}

// readerTier maps the calibrated tier to the reader's prompt variant.
func readerTier(t calibrate.Tier) (reader.Tier, error) {
	switch t {
	case calibrate.TierS:
		return reader.TierS, nil
	case calibrate.TierM:
		return reader.TierM, nil
	case calibrate.TierL:
		return reader.TierL, nil
	}
	return "", fmt.Errorf("tier %q: %w", string(t), errUnmapped)
}

// discoverTier maps the calibrated tier to discovery's prompt and batch
// budget.
func discoverTier(t calibrate.Tier) (discover.Tier, error) {
	switch t {
	case calibrate.TierS:
		return discover.TierS, nil
	case calibrate.TierM:
		return discover.TierM, nil
	case calibrate.TierL:
		return discover.TierL, nil
	}
	return "", fmt.Errorf("tier %q: %w", string(t), errUnmapped)
}

// readerClass maps a hypothesis class to the reader's.
func readerClass(c planner.Class) (reader.Class, error) {
	switch c {
	case planner.ClassSQLInjection:
		return reader.ClassSQLInjection, nil
	case planner.ClassCommandInjection:
		return reader.ClassCommandInjection, nil
	case planner.ClassPathTraversal:
		return reader.ClassPathTraversal, nil
	case planner.ClassSSRF:
		return reader.ClassSSRF, nil
	case planner.ClassTemplateInjection:
		return reader.ClassTemplateInjection, nil
	case planner.ClassNoSQLInjection:
		return reader.ClassNoSQLInjection, nil
	}
	return 0, fmt.Errorf("class %d: %w", c, errUnmapped)
}

// plannerInput copies discovery's IDs, enums and booleans, and nothing
// else, into the planner's input (invariant 3): no path, span or line
// reaches it. Discovery already forced every flag to the worst case
// (ADR 0017); they are copied as they are, never recomputed here. Sinks of
// an unmapped kind are returned apart so the report lists them as not
// evaluated.
func plannerInput(res discover.Result, tier planner.Tier, budget planner.Budget) (planner.Input, []discover.SinkID) {
	in := planner.Input{Tier: tier, Budget: budget, Routes: make([]planner.Route, len(res.Routes))}
	for i, r := range res.Routes {
		in.Routes[i] = planner.Route{ID: planner.RouteID(r.ID), Methods: plannerMethods(r.Methods), Authenticated: r.Authenticated}
	}
	var unmapped []discover.SinkID
	for _, s := range res.Sinks {
		kind, err := plannerKind(s.Kind)
		if err != nil {
			unmapped = append(unmapped, s.ID)
			continue
		}
		in.Sinks = append(in.Sinks, planner.Sink{
			ID: planner.SinkID(s.ID), Route: planner.RouteID(s.Route), Kind: kind,
			DynamicArg: s.DynamicArg, Parameterized: s.Parameterized, Indirect: s.Indirect,
		})
	}
	return in, unmapped
}
