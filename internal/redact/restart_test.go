package redact

import (
	"fmt"
	"math/rand/v2"
	"strings"
	"testing"
)

// denseKeyBlock returns about size bytes of .env lines whose long names give
// the generic rule a match at every byte (issue #107), and their values.
func denseKeyBlock(rng *rand.Rand, size int) (string, []string) {
	var b strings.Builder
	var values []string
	for b.Len() < size {
		v := fakeToken(rng, alnum, 120)
		values = append(values, v)
		b.WriteString("SERVICE_ACCOUNT_PRIMARY_REGION_DEFAULT_SECONDARY_TOKEN=" + v + "\n")
	}
	return b.String(), values
}

// codeBlock returns about size bytes of code that no detector matches.
func codeBlock(size int) string {
	var b strings.Builder
	for i := 0; b.Len() < size; i++ {
		fmt.Fprintf(&b, "func f%d(a int) string { return fmt.Sprintf(\"%%d\", a+%d) }\n", i, i)
	}
	return b.String()
}

// Acceptance (#107): 16 KiB of dense key lines followed by code run the
// generic rule out of budget, yet the code stays visible byte for byte and
// every key value is still masked, through Redact and File.
func TestDenseKeysKeepCodeVisible(t *testing.T) {
	rng := rand.New(rand.NewPCG(107, 1))
	keys, values := denseKeyBlock(rng, 16<<10)
	tests := []struct{ name, before, after string }{
		{"keys then code", "", codeBlock(MaxInputBytes - len(keys) - 100)},
		{"code, keys, code", codeBlock(16 << 10), codeBlock(30 << 10)},
	}
	for _, tt := range tests {
		text := tt.before + keys + tt.after
		if !budgetRunsOut(t, text) {
			t.Fatalf("%s: the generic rule kept within its budget; the test needs it spent", tt.name)
		}
		viaFile, err := newRedactor(t).File([]byte(text))
		if err != nil {
			t.Fatal(err)
		}
		for _, out := range []string{mustRedact(t, newRedactor(t), text), viaFile} {
			if !strings.HasPrefix(out, tt.before) || !strings.HasSuffix(out, tt.after) {
				t.Errorf("%s: a span crossed into the code", tt.name)
			}
			if w := leakedWindow(windows(values), out); w != "" {
				t.Fatalf("%s: key value leaked: %q", tt.name, w)
			}
		}
	}
}

// budgetRunsOut reports whether the generic rule gives up a line on text.
func budgetRunsOut(t *testing.T, text string) bool {
	t.Helper()
	rules, err := defaultRules()
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rules {
		if r.label != "SECRET_GENERIC_API_KEY" {
			continue
		}
		for _, sp := range r.find(text) {
			if sp.guess {
				return true
			}
		}
	}
	return false
}

// When the budget runs out, find masks to the end of the current line only,
// then searches the next lines again; a guess is never remembered alone.
func TestFindGivesUpOneLine(t *testing.T) {
	dense := strings.Repeat(" ", 4096) + "k=" + strings.Repeat("w", 8192)
	text := dense + "\n k=second\nplain tail\n"
	spans := overlapRule().find(text)
	var guesses []span
	found := false
	for _, sp := range spans {
		if sp.guess {
			guesses = append(guesses, sp)
		}
		found = found || text[sp.start:sp.end] == "second"
	}
	if len(guesses) != 1 || guesses[0].end != len(dense) || guesses[0].start >= 4096 {
		t.Fatalf("guesses %v, want one up to the first newline (%d)", guesses, len(dense))
	}
	if !found {
		t.Fatal("the line after the given-up one was not searched")
	}
	r := newRedactor(t)
	r.state.rememberParts(text, guesses)
	if len(r.state.byValue) != 0 {
		t.Fatal("a guess was remembered as a value")
	}
}

// Every line dense: each is given up in turn, the total stops the search,
// and no byte after the first restart is ever left unmasked.
func TestFindTotalMasksRest(t *testing.T) {
	line := strings.Repeat(" ", 2048) + "k=" + strings.Repeat("w", 4096) + "\n"
	text := strings.Repeat(line, 10)
	spans := mergeSpans(overlapRule().find(text))
	if last := spans[len(spans)-1]; last.end != len(text) || len(spans) >= 10 {
		t.Fatalf("spans %v, want the total spent before the last line, then the rest masked", spans)
	}
	covered := make([]bool, len(text))
	for _, sp := range spans {
		for i := sp.start; i < sp.end; i++ {
			covered[i] = true
		}
	}
	for i := range text {
		if text[i] == 'w' && !covered[i] {
			t.Fatalf("byte %d of a match left unmasked", i)
		}
	}
	lim := newRestartLimits(text)
	if lim.total-lim.line != max(len(text), minRestartBudgetBase) {
		t.Fatalf("limits %+v, want the total one text length above the line budget", lim)
	}
}
