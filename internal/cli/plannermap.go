package cli

import (
	"errors"
	"fmt"

	"github.com/sneakercreepers/creep/internal/calibrate"
	"github.com/sneakercreepers/creep/internal/planner"
	"github.com/sneakercreepers/creep/internal/reader"
	"github.com/sneakercreepers/creep/internal/static"
)

// The planner may not import static, calibrate or reader (invariant 3 and
// the layer table), and its enums repeat their numeric values. A numeric
// cast would pass a value added on one side straight through, so each value
// is mapped by an explicit switch; plannermap_test.go fails when either side
// gains a value this file does not name.

// errUnmapped means a value has no mapping here; the scan fails closed.
var errUnmapped = errors.New("no planner mapping")

// pendingKinds are static sink kinds the planner and reader cannot take yet,
// with the issue that adds them. Their sinks are listed as not evaluated
// (unmapped_kind) and the run is incomplete. plannermap_test.go fails if one
// gets a mapping without leaving this list, or if any other kind is unmapped.
// It is empty since #212 mapped SinkNoSQL.
var pendingKinds = map[static.SinkKind]string{}

// plannerKind maps a static sink kind. An unmapped kind (a new static kind
// before the planner learns it) is listed as not evaluated, never planned.
func plannerKind(k static.SinkKind) (planner.SinkKind, error) {
	switch k {
	case static.SinkSQL:
		return planner.SinkSQL, nil
	case static.SinkShell:
		return planner.SinkShell, nil
	case static.SinkFile:
		return planner.SinkFile, nil
	case static.SinkHTTPClient:
		return planner.SinkHTTPClient, nil
	case static.SinkTemplate:
		return planner.SinkTemplate, nil
	case static.SinkNoSQL:
		return planner.SinkNoSQL, nil
	}
	return 0, fmt.Errorf("sink kind %d: %w", k, errUnmapped)
}

// plannerMethods maps each method bit. An unknown bit becomes MethodOther,
// which the planner ranks as state-changing: the safe direction.
func plannerMethods(m static.Methods) planner.Methods {
	var out planner.Methods
	for bit := static.Methods(1); bit != 0; bit <<= 1 {
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

func plannerMethod(bit static.Methods) (planner.Methods, bool) {
	switch bit {
	case static.MethodGet:
		return planner.MethodGet, true
	case static.MethodPost:
		return planner.MethodPost, true
	case static.MethodPut:
		return planner.MethodPut, true
	case static.MethodPatch:
		return planner.MethodPatch, true
	case static.MethodDelete:
		return planner.MethodDelete, true
	case static.MethodHead:
		return planner.MethodHead, true
	case static.MethodOptions:
		return planner.MethodOptions, true
	case static.MethodTrace:
		return planner.MethodTrace, true
	case static.MethodOther:
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

// plannerInput copies the graph's IDs, enums and booleans, and nothing else,
// into the planner's input. Sinks of an unmapped kind are returned apart so
// the report lists them as not evaluated.
func plannerInput(g static.Graph, tier planner.Tier, budget planner.Budget) (planner.Input, []static.SinkID) {
	in := planner.Input{Tier: tier, Budget: budget, Routes: make([]planner.Route, len(g.Routes))}
	for i, r := range g.Routes {
		in.Routes[i] = planner.Route{ID: planner.RouteID(r.ID), Methods: plannerMethods(r.Methods), Authenticated: r.Auth != 0}
	}
	var unmapped []static.SinkID
	for _, s := range g.Sinks {
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
