package discover

import (
	"cmp"
	"slices"
)

// assemble builds the Result: files in input order, then routes and sinks
// with IDs creep assigns in path, line and kind order. Tripwire hits and
// model proposals of every sample are combined by union only: a candidate
// any of them names is kept, and one several name is one sink with every
// origin, counted once per sample that named it.
func assemble(work []fileWork, samples uint8) Result {
	res := Result{Files: make([]File, len(work)), Samples: samples}
	for i := range work {
		if work[i].file.Coverage == 0 { // never decided: fail closed
			work[i].fail(CoverageSendFailed, ReasonSendFailed)
		}
		res.Files[i] = work[i].file
	}
	order := make([]int, len(work))
	for i := range order {
		order[i] = i
	}
	slices.SortStableFunc(order, func(a, b int) int { return cmp.Compare(work[a].path, work[b].path) })
	for _, i := range order {
		res.addFile(&work[i])
	}
	return res
}

// addFile adds one file's routes, sinks and auth spans.
func (res *Result) addFile(w *fileWork) {
	entries := uniqueEntries(w.entries)
	first := RouteID(len(res.Routes) + 1) //nolint:gosec // G115: bounded by files times MaxEntriesPerFile
	for _, e := range entries {
		res.addRoute(w.file.ID, e.lines, e.kind, false)
	}
	var fileRoute RouteID
	for _, s := range unionSinks(w.hits, w.sinks, res.Samples) {
		route := routeFor(entries, first, s.prop)
		if route == 0 {
			if fileRoute == 0 {
				fileRoute = res.addRoute(w.file.ID, Span{Start: 1, End: 1}, 0, true)
			}
			route = fileRoute
		}
		res.Sinks = append(res.Sinks, Sink{
			ID: SinkID(len(res.Sinks) + 1), Route: route, File: w.file.ID, //nolint:gosec // G115: bounded by files times the caps
			Line: s.prop.line, Kind: s.prop.kind, Origin: s.origin,
			SeenBy:     s.prop.samples,
			DynamicArg: true, Parameterized: false, Indirect: false,
		})
	}
	for _, a := range uniqueSpans(w.auth) {
		res.Auth = append(res.Auth, AuthSpan{File: w.file.ID, Lines: a})
	}
}

// addRoute appends a route at the planner's worst case: every method,
// not authenticated.
func (res *Result) addRoute(file FileID, lines Span, kind EntryKind, fileLevel bool) RouteID {
	id := RouteID(len(res.Routes) + 1) //nolint:gosec // G115: bounded by files times MaxEntriesPerFile
	res.Routes = append(res.Routes, Route{
		ID: id, File: file, Lines: lines, Kind: kind,
		Methods: AllMethods, Authenticated: false, FileLevel: fileLevel,
	})
	return id
}

// candidate is a sink after union, with every origin that named it.
type candidate struct {
	prop   sinkProp
	origin Origin
}

// unionSinks merges hits and proposals by line and kind, sorted. The first
// model link to an entry wins; a link never removes a candidate. A
// tripwire hit needs no model, so every one of the run's samples names it.
func unionSinks(hits []hit, props []sinkProp, samples uint8) []candidate {
	every := uint8(1<<samples - 1)
	var all []candidate
	for _, h := range hits {
		all = append(all, candidate{prop: sinkProp{line: h.line, kind: h.kind, samples: every}, origin: OriginTripwire})
	}
	for _, p := range props {
		all = append(all, candidate{prop: p, origin: OriginModel})
	}
	slices.SortStableFunc(all, func(a, b candidate) int {
		return cmp.Or(cmp.Compare(a.prop.line, b.prop.line), cmp.Compare(a.prop.kind, b.prop.kind))
	})
	var out []candidate
	for _, c := range all {
		k := len(out) - 1
		if k < 0 || out[k].prop.line != c.prop.line || out[k].prop.kind != c.prop.kind {
			out = append(out, c)
			continue
		}
		out[k].origin |= c.origin
		out[k].prop.samples |= c.prop.samples
		if !out[k].prop.hasEntry && c.prop.hasEntry {
			out[k].prop.entry, out[k].prop.hasEntry = c.prop.entry, true
		}
	}
	return out
}

// routeFor returns the route a sink belongs to: the entry the model linked
// it to, else the innermost proposed entry whose lines hold it, else 0 for
// the file-level route. entries are the file's routes from first on.
func routeFor(entries []entryProp, first RouteID, s sinkProp) RouteID {
	best := -1
	for i, e := range entries {
		if s.hasEntry {
			if e.lines == s.entry {
				return first + RouteID(i) //nolint:gosec // G115: i < MaxEntriesPerFile per reply
			}
			continue
		}
		if e.lines.Start <= s.line && s.line <= e.lines.End && (best < 0 || width(e.lines) < width(entries[best].lines)) {
			best = i
		}
	}
	if best < 0 {
		return 0
	}
	return first + RouteID(best) //nolint:gosec // G115: as above
}

func width(s Span) uint32 { return s.End - s.Start }

// uniqueEntries sorts entries by lines and kind and drops exact repeats.
func uniqueEntries(entries []entryProp) []entryProp {
	out := slices.Clone(entries)
	slices.SortFunc(out, func(a, b entryProp) int {
		return cmp.Or(compareSpans(a.lines, b.lines), cmp.Compare(a.kind, b.kind))
	})
	return slices.Compact(out)
}

func uniqueSpans(spans []Span) []Span {
	out := slices.Clone(spans)
	slices.SortFunc(out, compareSpans)
	return slices.Compact(out)
}

func compareSpans(a, b Span) int {
	return cmp.Or(cmp.Compare(a.Start, b.Start), cmp.Compare(a.End, b.End))
}
