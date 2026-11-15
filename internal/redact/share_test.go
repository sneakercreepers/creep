package redact

import (
	"errors"
	"fmt"
	"maps"
	"math/rand/v2"
	"reflect"
	"strings"
	"testing"
)

// storeOutsideCall stores value as if each came from a call of its own, so
// tests can fill the run's caps without meeting the per-call share.
func storeOutsideCall(s *runState, value string) {
	s.call = callShare{}
	s.marker(value, "SECRET_TEST")
	s.call = callShare{}
}

// placeholderFile holds n password values of one repeated byte, each a
// different length: every window of each is the same, so past the first 16
// they can only go to the overflow list (issue #105).
func placeholderFile(c byte, n int) string {
	var b strings.Builder
	for i := range n {
		fmt.Fprintf(&b, "password = %s\n", strings.Repeat(string(c), minSweepLen+i))
	}
	return b.String()
}

// knownBefore holds a value the run stores before a crafted file arrives.
const knownBefore = "token = \"Q7xZ9kLm" + "P4r2Wv8s\"\n"

// snapshot copies the run state that a failed call must leave as it was.
type snapshot struct {
	byValue, byMarker map[string]string
	counters          map[string]int
	bytes             int
	values            []sweepValue
	windows           map[uint64][]int
	overflow          [256][]int
	overflowCount     int
}

func snap(s *runState) snapshot {
	out := snapshot{
		byValue: maps.Clone(s.byValue), byMarker: maps.Clone(s.byMarker), counters: maps.Clone(s.counters),
		bytes: s.bytes, values: append([]sweepValue(nil), s.index.values...), windows: map[uint64][]int{},
		overflowCount: s.index.overflowCount,
	}
	for w, ids := range s.index.windows {
		out.windows[w] = append([]int(nil), ids...)
	}
	for i, ids := range s.index.overflow {
		if len(ids) > 0 {
			out.overflow[i] = append([]int(nil), ids...)
		}
	}
	return out
}

// Acceptance (#105): one crafted file cannot fill the run. It fails alone
// with ErrTooManyValues and no output, leaves the run as it was, and every
// later file is still redacted, its values re-masked in later fragments.
func TestCraftedFileCannotFillRun(t *testing.T) {
	tests := []struct {
		name string
		file string
	}{
		{"issue size", placeholderFile('x', 272)},
		{"1000 lengths", placeholderFile('x', 1000)},
		{"just over the share", placeholderFile('y', maxWindowValues+maxCallOverflow+1)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newRedactor(t)
			mustRedact(t, r, knownBefore)
			before := snap(r.state)
			out, err := r.File([]byte(tt.file))
			if !errors.Is(err, ErrTooManyValues) || out != "" {
				t.Fatalf("File = %d bytes, %v; want no output and ErrTooManyValues", len(out), err)
			}
			if after := snap(r.state); !reflect.DeepEqual(before, after) {
				t.Fatal("the failed call changed the run state")
			}
			assertRunGoesOn(t, r)
		})
	}
}

// assertRunGoesOn checks the run still masks old and new values, with the
// markers of a run that never saw the failed call.
func assertRunGoesOn(t *testing.T, r *Redactor) {
	t.Helper()
	control := newRedactor(t)
	mustRedact(t, control, knownBefore)
	later := "Hk2p" + "R9wQ4zXv" // split: no literal credential in this file
	for _, text := range []string{"reuse Q7xZ9kLmP4r2Wv8s\n", "password = " + later + "\n", "x := " + later + "\n"} {
		out, err := r.File([]byte(text))
		if want := mustRedact(t, control, text); err != nil || out != want {
			t.Fatalf("File(%q) = %q, %v; want %q", text, out, err, want)
		}
		if strings.Contains(out, "Q7xZ9kLm") || strings.Contains(out, "Hk2pR9wQ") {
			t.Fatalf("a value leaked after the failed call: %q", out)
		}
	}
}

// A file that stays within the share is redacted whole, and its values are
// re-masked bare later in the run.
func TestPlaceholdersWithinShareKept(t *testing.T) {
	r := newRedactor(t)
	file := placeholderFile('z', maxWindowValues+maxCallOverflow)
	out, err := r.File([]byte(file))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "zzzzzzzz") {
		t.Fatalf("placeholder leaked: %q", out)
	}
	bare := strings.ReplaceAll(strings.ReplaceAll(file, "password = ", "x := "), "\"", "")
	if out := mustRedact(t, r, bare); strings.Contains(out, "zzzzzzzz") {
		t.Fatalf("placeholder not re-masked bare: %q", out)
	}
}

// The reachable limit: eight files at the overflow share fill the overflow
// list, so the ninth ends the run (ErrRunFull), failing closed.
func TestOverflowListLimitIsPinned(t *testing.T) {
	r := newRedactor(t)
	for i := range maxOverflowValues / maxCallOverflow {
		// One window per byte holds 16, so each file uses its own byte.
		if _, err := r.File([]byte(placeholderFile(byte('a'+i), maxWindowValues+maxCallOverflow))); err != nil {
			t.Fatalf("file %d: %v", i, err)
		}
	}
	if r.state.index.overflowCount != maxOverflowValues {
		t.Fatalf("overflow list holds %d, want %d", r.state.index.overflowCount, maxOverflowValues)
	}
	if _, err := r.File([]byte(placeholderFile('q', maxWindowValues+1))); !errors.Is(err, ErrRunFull) {
		t.Fatalf("err = %v, want ErrRunFull once the list is full", err)
	}
}

// The share bounds values and bytes as well as overflow slots, and the run's
// own caps still end the run when a call within its share reaches them.
func TestCallShareBounds(t *testing.T) {
	tests := []struct {
		name  string
		share callShare
		value string
		want  bool
	}{
		{"empty", callShare{}, "v", true},
		{"last value", callShare{added: make([]string, maxCallValues-1)}, "v", true},
		{"values full", callShare{added: make([]string, maxCallValues)}, "v", false},
		{"last byte", callShare{bytes: maxCallBytes - 1}, "v", true},
		{"bytes full", callShare{bytes: maxCallBytes - 1}, "vv", false},
		{"already over", callShare{over: true}, "v", false},
	}
	for _, tt := range tests {
		c := tt.share
		if got := c.admits(tt.value); got != tt.want || c.over == tt.want {
			t.Errorf("%s: admits = %t (over %t), want %t", tt.name, got, c.over, tt.want)
		}
	}
	r := newRedactor(t)
	r.state.bytes = maxRunBytes - 5
	if _, err := r.Redact("mail alice.smith@example.com\n"); !errors.Is(err, ErrRunFull) {
		t.Fatalf("err = %v, want ErrRunFull: the run cap comes first", err)
	}
}

// Acceptance (#105): a file of several chunks holding an unterminated private
// key adds about its own size to the run's byte count, not twice it (its body
// is not stored again apart from its header), so the byte cap holds about 32
// files at MaxFileBytes. A quarter of MaxFileBytes keeps the test fast.
func TestFileKeyCountsOnce(t *testing.T) {
	rng := rand.New(rand.NewPCG(105, 2))
	body := fakeBody(rng, MaxFileBytes/4, 64)
	file := pemEdge("BEGIN", "RSA") + "\n" + strings.Join(body, "\n")
	r := newRedactor(t)
	out, err := r.File([]byte(file))
	if err != nil {
		t.Fatal(err)
	}
	assertNoBody(t, body[:len(body)-1], out)
	if limit := len(file) + len(file)/16; r.state.bytes > limit {
		t.Fatalf("%d bytes stored for a %d-byte file, want at most %d", r.state.bytes, len(file), limit)
	}
}

// Fail closed: a file with secrets and too many placeholders returns none of
// its text, so no secret in it is ever sent.
func TestTooManyValuesReturnsNothing(t *testing.T) {
	rng := rand.New(rand.NewPCG(105, 1))
	secret := fakeGitHub(rng)
	file := "cfg := \"" + secret + "\"\n" + placeholderFile('x', 300)
	out, err := newRedactor(t).File([]byte(file))
	if !errors.Is(err, ErrTooManyValues) || out != "" {
		t.Fatalf("File = %d bytes, %v; want nothing", len(out), err)
	}
}
