package redact

import (
	"context"
	"errors"
	"maps"
	"math/rand/v2"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// findAll is every occurrence the sweep sees, by bounds only: the reference
// that the search per value (indexSweep) must equal.
func findAll(t *testing.T, x *sweepIndex, text string) []span {
	t.Helper()
	spans, err := x.scanText(text, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	for i := range spans {
		spans[i].known = ""
	}
	return spans
}

// sweepLabels are the labels the randomized tests give known values: personal
// data, the generic rule, the password detector and a rule that knows its
// format, so every rank of labelRank meets every other.
var sweepLabels = []string{"PII_EMAIL", genericLabel, passwordLabel, "SECRET_GITHUB_PAT", secretPrefix + "VALUE"}

// Protection (#106): find drops only an occurrence that lies inside a kept
// one of the same label, and keeps nothing the search per value does not
// find, so it masks exactly the bytes every occurrence masks.
func TestSweepKeepsCoverOfEveryOccurrence(t *testing.T) {
	rng := rand.New(rand.NewPCG(106, 1))
	for round := range 400 {
		text := fakeToken(rng, "ab", 100+rng.IntN(300))
		x := newSweepIndex()
		for range 1 + rng.IntN(20) {
			start := rng.IntN(len(text) - 40)
			value := text[start : start+minSweepLen+rng.IntN(30)]
			x.add(value, sweepLabels[rng.IntN(len(sweepLabels))], true)
		}
		all, err := x.scanText(text, nil, true)
		if err != nil {
			t.Fatal(err)
		}
		kept, err := x.find(text, nil)
		if err != nil {
			t.Fatal(err)
		}
		assertKeptCoverAll(t, round, kept, all)
	}
}

func assertKeptCoverAll(t *testing.T, round int, kept, all []span) {
	t.Helper()
	for _, k := range kept {
		if !slices.Contains(all, k) {
			t.Fatalf("round %d: kept %v is no occurrence", round, k)
		}
	}
	for _, a := range all {
		if !slices.ContainsFunc(kept, func(k span) bool {
			return k.known == a.known && k.start <= a.start && a.end <= k.end
		}) {
			t.Fatalf("round %d: %v lies inside no kept occurrence of its label; kept %v", round, a, kept)
		}
	}
}

// Protection (#106): rendering with only the kept occurrences writes the same
// text and stores the same values as rendering with every occurrence, also
// next to detector spans of every rank and in text with format characters.
func TestSweepKeptRenderAsEveryOccurrence(t *testing.T) {
	rng := rand.New(rand.NewPCG(106, 2))
	for round := range 300 {
		text := fakeToken(rng, "ab@", 200+rng.IntN(200))
		if round%3 == 0 {
			i := rng.IntN(len(text))
			text = text[:i] + zwsp + text[i:]
		}
		var values [][2]string
		for range 1 + rng.IntN(16) {
			start := rng.IntN(len(text) - 40)
			values = append(values, [2]string{text[start : start+minSweepLen+rng.IntN(30)], sweepLabels[rng.IntN(len(sweepLabels))]})
		}
		detected := randomSpans(rng, len(text))
		want, wantStored := renderSwept(t, values, text, detected, true)
		got, gotStored := renderSwept(t, values, text, detected, false)
		if got != want || !maps.Equal(gotStored, wantStored) {
			t.Fatalf("round %d: kept occurrences render\n%q\nevery occurrence renders\n%q", round, got, want)
		}
	}
}

// Protection (#106): for any text and any known values cut from it, the kept
// occurrences cover every occurrence by label and render alike.
func FuzzSweepKeepsEveryOccurrence(f *testing.F) {
	f.Add("abababababaabbabab@a@abbbababababbababbaab", uint64(1))
	f.Add(strings.Repeat("e", 60)+"\n"+strings.Repeat("e", 30), uint64(2))
	f.Add("ab"+zwsp+"abababababab"+zwsp+"ababababab@abababab", uint64(3))
	f.Fuzz(func(t *testing.T, text string, seed uint64) {
		if len(text) < 2*minSweepLen || len(text) > 4096 {
			return
		}
		rng := rand.New(rand.NewPCG(seed, 106))
		var values [][2]string
		for range 1 + rng.IntN(12) {
			start := rng.IntN(len(text) - minSweepLen)
			end := start + minSweepLen + rng.IntN(len(text)-start-minSweepLen+1)
			values = append(values, [2]string{text[start:end], sweepLabels[rng.IntN(len(sweepLabels))]})
		}
		detected := randomSpans(rng, len(text))
		want, wantStored := renderSwept(t, values, text, detected, true)
		got, gotStored := renderSwept(t, values, text, detected, false)
		if got != want || !maps.Equal(gotStored, wantStored) {
			t.Fatalf("kept occurrences render\n%q\nevery occurrence renders\n%q", got, want)
		}
	})
}

// randomSpans are detector spans with random bounds and labels.
func randomSpans(rng *rand.Rand, n int) []span {
	var spans []span
	for range rng.IntN(4) {
		start := rng.IntN(n)
		end := min(n, start+1+rng.IntN(20))
		spans = append(spans, span{start: start, end: end, label: sweepLabels[rng.IntN(len(sweepLabels))]})
	}
	return spans
}

// renderSwept stores values in a new run, then renders text with the
// detected spans and the sweep's, as finish does, and returns the output and
// the values the run then holds. It needs no rules, so it builds the run
// state alone: compiling the rules for each round would dominate -race runs.
func renderSwept(t *testing.T, values [][2]string, text string, detected []span, keepAll bool) (string, map[string]string) {
	t.Helper()
	s := &runState{byValue: map[string]string{}, byMarker: map[string]string{}, counters: map[string]int{}, index: newSweepIndex()}
	for _, v := range values {
		s.call = callShare{}
		s.marker(v[0], v[1])
	}
	s.call = callShare{}
	found := slices.Clone(detected)
	found = append(found, withoutFormat(text, func(text string) []span {
		spans, err := s.index.scanText(text, nil, keepAll)
		if err != nil {
			t.Fatal(err)
		}
		return spans
	})...)
	out := s.render(text, mergeSpans(found), found)
	s.rememberParts(text, found)
	return out, s.byValue
}

// A swept part takes the label of its value's marker, as the run stores it.
func TestSweepKnowsStoredLabel(t *testing.T) {
	r := newRedactor(t)
	values := map[string]string{"alice.smith@example.com": "PII_EMAIL", "Q7xZ9kLmP4r2": passwordLabel, "Zp4QxW8rT2": ""}
	for v, label := range values {
		r.state.marker(v, label)
	}
	text := "a alice.smith@example.com b Q7xZ9kLmP4r2 c Zp4QxW8rT2"
	spans, err := r.state.index.find(text, nil)
	if err != nil || len(spans) != len(values) {
		t.Fatalf("find = %v, %v; want one span per value", spans, err)
	}
	for _, sp := range spans {
		m := r.state.byValue[text[sp.start:sp.end]]
		if want := m[1:strings.LastIndexByte(m, '_')]; sp.known != want {
			t.Errorf("%q: known %q, want %q", text[sp.start:sp.end], sp.known, want)
		}
	}
}

// Protection (#106): with the overflow list full, a run of one byte keeps one
// span, not one per known run of it per position.
func TestSweepOneByteRunKeepsOneSpan(t *testing.T) {
	r := overflowFull(t)
	line := strings.Repeat("e", minSweepLen+maxWindowValues+maxOverflowValues-1)
	text := strings.Repeat(line+"\n", 4)
	spans, err := r.state.index.find(text, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(spans) != 4 {
		t.Fatalf("find kept %d spans, want one per line: %v", len(spans), spans)
	}
	out := mustRedact(t, r, text)
	if strings.Contains(out, "eeeeeeee") {
		t.Fatalf("a run leaked: %q", out[:200])
	}
}

// Protection (#106): text that keeps more occurrences than the limit, here
// runs of one byte stored under a different label each, so none nests in
// another of its label, fails closed: no output, nothing stored, and the run
// goes on.
func TestSweepOverLimitFailsClosed(t *testing.T) {
	r := newRedactor(t)
	for i := range maxWindowValues + maxOverflowValues {
		r.state.call = callShare{}
		r.state.marker(strings.Repeat("e", minSweepLen+i), "SECRET_T"+strconv.Itoa(i))
	}
	r.state.call = callShare{}
	stored := len(r.state.byValue)
	line := strings.Repeat("e", minSweepLen+maxWindowValues+maxOverflowValues-1) + "\n"
	// Each line keeps one span per value, 272 in 280 bytes: 8 lines keep
	// 2176, over the limit of 1584 for their 2240 bytes.
	text := strings.Repeat(line, 8)
	for _, file := range []bool{false, true} {
		out, err := redactOrFile(r, text, file)
		if !errors.Is(err, ErrTooManyValues) || out != "" {
			t.Fatalf("file=%t: %d bytes, %v; want no output and ErrTooManyValues", file, len(out), err)
		}
		if len(r.state.byValue) != stored {
			t.Fatalf("file=%t: %d values stored, want %d", file, len(r.state.byValue), stored)
		}
	}
	if out := mustRedact(t, r, "x := "+line); strings.Contains(out, "eeeeeeee") {
		t.Fatalf("the run did not go on: %q", out)
	}
}

func redactOrFile(r *Redactor, text string, file bool) (string, error) {
	if file {
		return r.File([]byte(text))
	}
	return r.Redact(text)
}

// Protection (#260, #106): the sweep stops once the run's context is done and
// returns its cause, never the spans found so far.
func TestSweepStopsWithContext(t *testing.T) {
	ctx, cancel := context.WithCancelCause(context.Background())
	r, err := NewWithContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	storeOutsideCall(r.state, "Q7xZ9kLmP4r2")
	text := strings.Repeat("Q7xZ9kLmP4r2 ", 1000)
	if spans, err := r.sweep(text); err != nil || len(spans) != 1000 {
		t.Fatalf("live sweep = %d spans, %v; want 1000", len(spans), err)
	}
	cancel(errTestDeadline)
	if spans, err := r.sweep(text); !errors.Is(err, errTestDeadline) || spans != nil {
		t.Fatalf("stopped sweep = %v, %v; want no spans and the cause", spans, err)
	}
	if spans, err := r.state.index.find(text, ctx.Done()); err != nil || spans != nil {
		t.Fatalf("stopped find = %v, %v; want nothing", spans, err)
	}
}

// Protection (#106): File on MaxFileBytes of one-byte runs with the overflow
// list full allocates under 150 MiB in all, so its peak heap is lower still.
func TestFileOverflowFullMemory(t *testing.T) {
	skipUnderRace(t)
	r := overflowFull(t)
	file := oneByteRuns()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	out, err := r.File(file)
	runtime.ReadMemStats(&after)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "eeeeeeee") {
		t.Fatal("a run leaked")
	}
	if got := after.TotalAlloc - before.TotalAlloc; got > 150<<20 {
		t.Fatalf("File allocated %d MiB, want under 150", got>>20)
	}
}
