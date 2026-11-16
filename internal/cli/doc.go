// Package cli parses the command line and dispatches to subcommands.
//
// It exists so that main stays a one-liner and the whole command surface
// (global flags, subcommands, usage text and exit codes) can be exercised in
// tests through Run without building or spawning a binary. It uses only the
// standard library flag package; no third-party CLI framework.
//
// It is also the only package above every pipeline layer, so `creep scan`
// wires them here (ADR 0009): calibrate the model, extract the static graph
// from the current directory, map it to planner values by explicit switch
// (plannermap.go; the planner may not import static, calibrate or reader),
// plan, slice and evaluate with the reader through the gateway and the
// record/replay cache, and build the report. Everything a run leaves out is
// listed as not evaluated, and a run that left out more than vendor code and
// tier S's low-risk sinks exits 4, never 0. `creep why` reads the last JSON
// report back strictly and prints a finding's evidence escaped.
//
// `creep estimate` (ADR 0010) runs the same static, planner and slicer code
// and hands each request to a send function with no transport, which
// measures it and refuses it, so an estimate never reaches a model or the
// network. `--stats` counts a scan's requests on both sides of the cache.
package cli
