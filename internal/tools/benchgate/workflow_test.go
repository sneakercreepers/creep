package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var (
	digestLine = regexp.MustCompile(`(?m)^      BASE_MODEL_DIGEST: ([0-9a-f]{64})$`)
	modelLine  = regexp.MustCompile(`(?m)^      BENCH_MODEL: (\S+)$`)
)

// The gate matches a baseline by contract and model name, so the nightly
// model's name must carry its digest: a re-pin then reads as another model
// and fails until the baseline is set again, instead of being compared with
// numbers another model produced.
func TestBenchModelNameCarriesDigest(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", ".github", "workflows", "bench.yml"))
	if err != nil {
		t.Fatal(err)
	}
	wf := strings.ReplaceAll(string(data), "\r\n", "\n")
	digest := digestLine.FindStringSubmatch(wf)
	model := modelLine.FindStringSubmatch(wf)
	if digest == nil || model == nil {
		t.Fatal("bench.yml: no BASE_MODEL_DIGEST or literal BENCH_MODEL in the local job")
	}
	if want := "-" + digest[1][:12]; !strings.HasSuffix(model[1], want) {
		t.Fatalf("BENCH_MODEL %q must end with %q", model[1], want)
	}
}

// A re-pinned model fails against the old baseline.
func TestRepinFailsAgainstOldBaseline(t *testing.T) {
	base := withModel(results(baseTier), "creep-bench-qwen2.5-coder-1.5b-d7372fd82851")
	got := withModel(results(baseTier), "creep-bench-qwen2.5-coder-1.5b-0123456789ab")
	problems, err := compare(base, got, DefaultMaxDrop)
	if err != nil {
		t.Fatal(err)
	}
	if len(problems) != 1 || !strings.Contains(problems[0], "set the baseline again") {
		t.Fatalf("problems %q, want one model mismatch", problems)
	}
}
