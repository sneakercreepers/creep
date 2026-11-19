package discover

import (
	"encoding/hex"
	"strings"
	"testing"
)

// The canary's token never occurs in the batch: a token the files already
// hold is skipped, and when every token tried occurs the batch is not sent
// and its files are parse_failed.
func TestCanaryAvoidsRepositoryText(t *testing.T) {
	base := []section{{work: 0, lang: 1, lines: []string{"import os"}}}
	tokens := make([]string, canaryAttempts)
	for i := range tokens {
		tokens[i] = hex.EncodeToString(canaryMAC(testSeed, i, renderBatch(base))[:canaryTokenBytes])
	}
	// Holding the first token changes the batch, so the next MAC differs;
	// the planted token must still be absent.
	withFirst := []section{{work: 0, lang: 1, lines: []string{"import os", "# " + tokens[0]}}}
	batch, _, ok := plantCanary(testSeed, withFirst)
	if !ok || strings.Count(renderBatch(batch), tokens[0]) != 1 {
		t.Errorf("planted batch holds the repository's token %d times, ok %v", strings.Count(renderBatch(batch), tokens[0]), ok)
	}
	for _, s := range batch {
		if s.work < 0 && strings.Contains(strings.Join(s.lines, "\n"), tokens[0]) {
			t.Error("the canary reused a token the batch holds")
		}
	}
}

func TestCanaryPlacement(t *testing.T) {
	positions := map[int]bool{}
	for b := range 64 {
		seed := testSeed
		seed[0] = byte(b)
		secs := []section{{work: 0, lines: []string{"a"}}, {work: 1, lines: []string{"b"}}}
		batch, c, ok := plantCanary(seed, secs)
		if !ok || len(batch) != 3 || batch[c.section].work != -1 {
			t.Fatalf("seed %d: canary at %d in %+v", b, c.section, batch)
		}
		lines := batch[c.section].lines
		if !strings.Contains(lines[c.entry-1], ".get(") || !strings.Contains(lines[c.sink-1], "fs.readFile(") {
			t.Fatalf("canary lines %d and %d are not its entry and sink: %q", c.entry, c.sink, lines)
		}
		for _, l := range lines {
			if strings.Contains(l, "{{") {
				t.Fatalf("unexpanded template line %q", l)
			}
		}
		positions[c.section] = true
	}
	if len(positions) != 3 {
		t.Errorf("canary took positions %v over 64 seeds, want all 3", positions)
	}
}

// Canary proposals never reach the Result: an honest reply about a batch
// of one empty-handed file yields no route or sink.
func TestCanaryNeverReachesResult(t *testing.T) {
	res, err := runPaths(t, TierM, []string{"a.py"}, map[string]string{"a.py": "x = 1\n"}, honestReply, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Routes) != 0 || len(res.Sinks) != 0 || fileOf(t, res, 0).Coverage != CoverageReadFull {
		t.Errorf("result %+v holds canary proposals", res)
	}
}
