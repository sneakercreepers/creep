// Command benchgate fails when a live creep bench run is worse than the
// committed baseline by more than the regression threshold (#36, ADR 0030
// amendment).
//
// The nightly bench workflow runs it on each run's results, and the
// release workflow runs it on the latest nightly results from main, so a
// release cannot be tagged past a regression. Per tier S, M and L it sums
// the counts of every class and compares three rates: recall and honesty
// may fall, and the false-positive rate may rise, by at most -max-drop
// (0.10). A rate the baseline measured and the results did not fails. A
// baseline measured on another corpus or model cannot be compared and
// fails until it is set again; a baseline without tiers is not set yet and
// passes. Synthesized results are refused: the gate measures a model.
//
// It reads two local JSON files and makes no network call. It is
// stdlib-only build tooling; the layers table (internal/tools/*) keeps it
// out of the binary.
package main
