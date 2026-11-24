package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sneakercreepers/creep/internal/bench"
)

// class builds one class row; rates are not read by the gate, which sums counts.
func class(name string, vulnerable, detected, safe, fps, claimed, silent int) bench.ClassResult {
	return bench.ClassResult{Class: name, Vulnerable: vulnerable, Detected: detected, Safe: safe,
		FalsePositives: fps, ClaimedCovered: claimed, SilentMisses: silent}
}

func results(tiers ...bench.TierResult) bench.Results {
	return bench.Results{
		SchemaVersion: bench.SchemaVersion,
		Corpus:        bench.CorpusInfo{Cases: 12, SHA256: "abc"},
		Model:         bench.ModelInfo{Contract: "openai", Name: "local"},
		Tiers:         tiers,
	}
}

func tier(name string, classes ...bench.ClassResult) bench.TierResult {
	return bench.TierResult{Tier: name, Classes: classes}
}

// baseTier is 10 vulnerable twins, 8 found; 10 safe, 1 flagged; 8 claimed
// covered, 1 silent miss.
var baseTier = tier("S", class("sqli", 6, 5, 6, 1, 5, 0), class("xss", 4, 3, 4, 0, 3, 1))

func TestCompare(t *testing.T) {
	tests := []struct {
		name string
		base bench.Results
		got  bench.Results
		want []string // substrings, one per expected problem; nil means none
	}{
		{"same numbers", results(baseTier), results(baseTier), nil},
		{"drop of exactly the threshold", results(baseTier),
			results(tier("S", class("sqli", 6, 4, 6, 1, 5, 0), class("xss", 4, 3, 4, 0, 3, 1))), nil},
		{"better everywhere", results(baseTier),
			results(tier("S", class("sqli", 6, 6, 6, 0, 6, 0), class("xss", 4, 4, 4, 0, 4, 0))), nil},
		{"recall drops", results(baseTier),
			results(tier("S", class("sqli", 6, 3, 6, 1, 5, 0), class("xss", 4, 3, 4, 0, 3, 1))), []string{"tier S: recall 0.600, baseline 0.800"}},
		{"false positives rise", results(baseTier),
			results(tier("S", class("sqli", 6, 5, 6, 3, 5, 0), class("xss", 4, 3, 4, 0, 3, 1))), []string{"false-positive rate 0.300, baseline 0.100"}},
		{"honesty drops", results(baseTier),
			results(tier("S", class("sqli", 6, 5, 6, 1, 5, 2), class("xss", 4, 3, 4, 0, 3, 1))), []string{"honesty 0.625, baseline 0.875"}},
		{"honesty becomes unmeasured", results(baseTier),
			results(tier("S", class("sqli", 6, 5, 6, 1, 0, 0), class("xss", 4, 3, 4, 0, 0, 0))), []string{"honesty was 0.875 and is now unmeasured"}},
		{"tier missing", results(baseTier, tier("M", class("sqli", 1, 1, 1, 0, 1, 0))), results(baseTier), []string{"tier M: in the baseline, missing"}},
		{"unmeasured in the baseline is not compared", results(tier("S", class("idor", 1, 0, 1, 0, 0, 0))),
			results(tier("S", class("idor", 1, 0, 1, 0, 0, 0))), nil},
		{"baseline not set", results(), results(tier("S", class("sqli", 1, 0, 1, 1, 0, 0))), nil},
		{"other corpus", results(baseTier), withCorpus(results(baseTier), "def"), []string{`corpus "def", baseline measured "abc"`}},
		{"other model", results(baseTier), withModel(results(baseTier), "bigger"), []string{`model openai "bigger"`}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := compare(tt.base, tt.got, DefaultMaxDrop)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("problems %q, want %d matching %q", got, len(tt.want), tt.want)
			}
			for i, w := range tt.want {
				if !strings.Contains(got[i], w) {
					t.Errorf("problem %q lacks %q", got[i], w)
				}
			}
		})
	}
}

func withCorpus(r bench.Results, sha string) bench.Results { r.Corpus.SHA256 = sha; return r }
func withModel(r bench.Results, name string) bench.Results { r.Model.Name = name; return r }

func TestCompareRefuses(t *testing.T) {
	synthesized := results(baseTier)
	synthesized.Model.Synthesized = true
	future := results(baseTier)
	future.SchemaVersion = bench.SchemaVersion + 1
	tests := []struct {
		name      string
		base, got bench.Results
	}{
		{"synthesized results", results(baseTier), synthesized},
		{"synthesized baseline", synthesized, results(baseTier)},
		{"unknown schema in results", results(baseTier), future},
		{"unknown schema in baseline", future, results(baseTier)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := compare(tt.base, tt.got, DefaultMaxDrop); err == nil {
				t.Fatal("compare accepted it")
			}
		})
	}
}

func writeJSON(t *testing.T, dir, name string, v any) string {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return writeFile(t, dir, name, string(data))
}

func writeFile(t *testing.T, dir, name, data string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRun(t *testing.T) {
	dir := t.TempDir()
	base := writeJSON(t, dir, "base.json", results(baseTier))
	same := writeJSON(t, dir, "same.json", results(baseTier))
	worse := writeJSON(t, dir, "worse.json", results(tier("S", class("sqli", 6, 0, 6, 1, 5, 0))))
	unset := writeJSON(t, dir, "unset.json", results())
	tests := []struct {
		name string
		args gateArgs
		code int
		want string
	}{
		{"no regression", gateArgs{base, same, DefaultMaxDrop}, 0, "ok, no tier worse"},
		{"regression", gateArgs{base, worse, DefaultMaxDrop}, 1, "regression: tier S: recall"},
		{"baseline not set", gateArgs{unset, worse, DefaultMaxDrop}, 0, "no baseline set yet"},
		{"no results flag", gateArgs{base, "", DefaultMaxDrop}, 2, "-results is required"},
		{"missing baseline", gateArgs{filepath.Join(dir, "absent"), same, DefaultMaxDrop}, 2, "baseline:"},
		{"missing results", gateArgs{base, filepath.Join(dir, "absent"), DefaultMaxDrop}, 2, "results:"},
		{"malformed results", gateArgs{base, writeFile(t, dir, "bad.json", "{"), DefaultMaxDrop}, 2, "decode"},
		{"trailing data", gateArgs{base, writeFile(t, dir, "trail.json", `{"schema_version":1} {}`), DefaultMaxDrop}, 2, "trailing data"},
		{"oversized results", gateArgs{base, writeFile(t, dir, "big.json", strings.Repeat(" ", maxResultsBytes+1)), DefaultMaxDrop}, 2, "over"},
		{"directory as results", gateArgs{base, dir, DefaultMaxDrop}, 2, "not a regular file"},
		{"negative threshold", gateArgs{base, same, -0.1}, 2, "outside 0 to 1"},
		{"threshold over one", gateArgs{base, same, 1.5}, 2, "outside 0 to 1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			if code := run(tt.args, &out); code != tt.code {
				t.Fatalf("exit %d, want %d: %s", code, tt.code, out.String())
			}
			if !strings.Contains(out.String(), tt.want) {
				t.Fatalf("output %q lacks %q", out.String(), tt.want)
			}
		})
	}
}

// The committed baseline must parse, never be synthesized, and once set
// measure the embedded corpus: a corpus change resets or re-measures it in
// the same pull request instead of failing the next nightly run.
func TestCommittedBaseline(t *testing.T) {
	base, err := readResults("baseline.json")
	if err != nil {
		t.Fatal(err)
	}
	if base.SchemaVersion != bench.SchemaVersion || base.Model.Synthesized {
		t.Fatalf("baseline.json: schema_version %d, synthesized %t", base.SchemaVersion, base.Model.Synthesized)
	}
	if len(base.Tiers) == 0 {
		return
	}
	digest, err := bench.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if base.Corpus.SHA256 != digest {
		t.Fatalf("baseline.json measured corpus %s, the embedded corpus is %s: set the baseline again", base.Corpus.SHA256, digest)
	}
}
