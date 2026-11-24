package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/sneakercreepers/creep/internal/bench"
)

// maxResultsBytes bounds each results file; the published one is ~20 KiB.
const maxResultsBytes = 8 << 20

// DefaultMaxDrop is the regression threshold (ADR 0030 amendment): a
// tier's recall or honesty may fall, or its false-positive rate rise, by
// at most this much against the baseline.
const DefaultMaxDrop = 0.10

// gateArgs name the two results files and the threshold.
type gateArgs struct {
	baseline, results string
	maxDrop           float64
}

func main() {
	var a gateArgs
	flag.StringVar(&a.baseline, "baseline", "internal/tools/benchgate/baseline.json", "committed baseline results (creep bench --format json)")
	flag.StringVar(&a.results, "results", "", "new results to check (creep bench --format json)")
	flag.Float64Var(&a.maxDrop, "max-drop", DefaultMaxDrop, "largest allowed drop in a tier's recall or honesty, or rise in its false-positive rate")
	flag.Parse()
	os.Exit(run(a, os.Stdout))
}

// run prints the verdict and returns 0 when nothing regressed or no
// baseline is set, 1 on a regression and 2 when an input cannot be read,
// so the gate fails closed.
func run(a gateArgs, out io.Writer) int {
	problems, notes, set, err := gate(a)
	if err != nil {
		fmt.Fprintln(out, "benchgate:", err)
		return 2
	}
	for _, n := range notes {
		fmt.Fprintln(out, "benchgate:", n)
	}
	for _, p := range problems {
		fmt.Fprintln(out, "benchgate: regression:", p)
	}
	switch {
	case len(problems) > 0:
		return 1
	case !set:
		fmt.Fprintln(out, "benchgate: no baseline set yet (no tiers in", a.baseline+"); nothing to compare")
	default:
		fmt.Fprintf(out, "benchgate: ok, no compared tier worse than the baseline by more than %.3f\n", a.maxDrop)
	}
	return 0
}

// gate returns the regressions, the tiers it did not compare and whether a
// baseline is set.
func gate(a gateArgs) (problems, notes []string, set bool, err error) {
	if a.results == "" {
		return nil, nil, false, errors.New("-results is required")
	}
	if a.maxDrop < 0 || a.maxDrop > 1 {
		return nil, nil, false, fmt.Errorf("-max-drop %v is outside 0 to 1", a.maxDrop)
	}
	base, err := readResults(a.baseline)
	if err != nil {
		return nil, nil, false, fmt.Errorf("baseline: %w", err)
	}
	got, err := readResults(a.results)
	if err != nil {
		return nil, nil, false, fmt.Errorf("results: %w", err)
	}
	problems, err = compare(base, got, a.maxDrop)
	return problems, noisyTiers(base, got), len(base.Tiers) > 0, err
}

// readResults decodes one results document. Unknown fields pass, since
// adding a field is compatible (ADR 0030); trailing data does not.
func readResults(name string) (bench.Results, error) {
	var r bench.Results
	data, err := readBounded(name)
	if err != nil {
		return r, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&r); err != nil {
		return r, fmt.Errorf("decode %s: %w", name, err)
	}
	if dec.More() {
		return r, fmt.Errorf("decode %s: trailing data", name)
	}
	return r, nil
}

func readBounded(name string) ([]byte, error) {
	f, err := os.OpenFile(name, os.O_RDONLY|nonblockFlag, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", name, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", name)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxResultsBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", name, err)
	}
	if len(data) > maxResultsBytes {
		return nil, fmt.Errorf("%s is over %d bytes", name, maxResultsBytes)
	}
	return data, nil
}
