package state

import (
	"bytes"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var digestA = strings.Repeat("a", 64)

// A run's header and step times come back from the log as written, across
// Load and Resume, so a resumed scan compares settings and keeps spending
// the original run's time (#335).
func TestHeaderAndElapsedRoundTrip(t *testing.T) {
	s := openStore(t)
	header := Header{"config": digestA, "model": strings.Repeat("b", 64)}
	r, err := s.NewRunWith(ModeRecord, header)
	if err != nil {
		t.Fatal(err)
	}
	steps := []struct {
		step  string
		spent time.Duration
	}{{"files:x", 0}, {"cache:1", 1500 * time.Millisecond}, {"cache:2", 900 * time.Millisecond}, {"cache:3", -time.Second}}
	for _, st := range steps {
		if err := r.StepDoneAt(st.step, st.spent); err != nil {
			t.Fatal(err)
		}
	}
	_ = r.Close()
	resumed, err := s.Resume(r.ID())
	if err != nil {
		t.Fatal(err)
	}
	defer resumed.Close()
	sum := resumed.Summary()
	if !maps.Equal(sum.Header, header) || sum.Mode != ModeRecord || sum.Elapsed != 1500*time.Millisecond || len(sum.Steps) != 4 {
		t.Fatalf("summary = %+v; want the header, mode record, 1.5s elapsed and 4 steps", sum)
	}
	sum.Header["config"] = strings.Repeat("c", 64)
	if resumed.Summary().Header["config"] != digestA {
		t.Fatal("Summary shares its header map with the run")
	}
}

// A header with text in it is refused before anything is written, and an
// old run without one reads with a nil header, which resume refuses.
func TestHeaderValidation(t *testing.T) {
	tests := []struct {
		name   string
		header Header
		ok     bool
	}{
		{"none", nil, true},
		{"digest", Header{"config": digestA}, true},
		{"clear value", Header{"endpoint": "https://models.example"}, false},
		{"upper-case digest", Header{"config": strings.ToUpper(digestA)}, false},
		{"name with spaces", Header{"a b": digestA}, false},
		{"too many fields", manyFields(maxHeaderFields + 1), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := openStore(t)
			r, err := s.NewRunWith(ModeLive, tt.header)
			if tt.ok != (err == nil) {
				t.Fatalf("NewRunWith err = %v; want ok %v", err, tt.ok)
			}
			if err != nil {
				if !errors.Is(err, ErrInvalidID) {
					t.Fatalf("err = %v; want ErrInvalidID", err)
				}
				return
			}
			_ = r.Close()
			sum, err := s.Load(r.ID())
			if err != nil || !maps.Equal(sum.Header, tt.header) {
				t.Fatalf("Load = %+v, %v", sum, err)
			}
		})
	}
}

// Editing the header on disk breaks the line's MAC: a run cannot be made
// to look as if it was started with the settings of a later scan.
func TestTamperedHeaderRefused(t *testing.T) {
	s := openStore(t)
	r, err := s.NewRunWith(ModeLive, Header{"config": digestA})
	if err != nil {
		t.Fatal(err)
	}
	_ = r.Close()
	path := filepath.Join(s.dir, runsDir, r.ID(), eventsFile)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	tampered := bytes.Replace(data, []byte(digestA), []byte(strings.Repeat("d", 64)), 1)
	if err := os.WriteFile(path, tampered, 0o600); err != nil { //nolint:gosec // G703: the store this test opened under t.TempDir()
		t.Fatal(err)
	}
	if _, err := s.Resume(r.ID()); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Resume of a tampered header err = %v; want ErrCorrupt", err)
	}
}

func manyFields(n int) Header {
	h := Header{}
	for i := range n {
		h["f"+string(rune('a'+i))] = digestA
	}
	return h
}

// Regression (v0.4 release pentest P5): a step's ms is read back only up to
// what a time.Duration holds, so no signed value wraps into a negative or
// small elapsed time; one past the bound is a corrupt line.
func TestStepMsFitsDuration(t *testing.T) {
	tests := []struct {
		name string
		ms   uint64
		ok   bool
	}{
		{"zero", 0, true},
		{"at the bound", maxStepMs, true},
		{"one past the bound", maxStepMs + 1, false},
		{"2^44, wrapped before the fix", 1 << 44, false},
		{"2^53, the old bound", 1 << 53, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := openStore(t)
			r, err := s.NewRunWith(ModeLive, Header{"config": digestA})
			if err != nil {
				t.Fatal(err)
			}
			if err := r.append(Event{Kind: KindStep, Step: "time:x", Ms: tt.ms}); err != nil {
				t.Fatal(err)
			}
			_ = r.Close()
			sum, err := s.Load(r.ID())
			if !tt.ok {
				if !errors.Is(err, ErrCorrupt) {
					t.Fatalf("Load err = %v; want ErrCorrupt", err)
				}
				return
			}
			if err != nil || sum.Elapsed < 0 || uint64(sum.Elapsed.Milliseconds()) != tt.ms { //nolint:gosec // G115: checked non-negative first
				t.Fatalf("Load = %v elapsed, %v; want %d ms", sum.Elapsed, err, tt.ms)
			}
		})
	}
}
