package verify

import (
	"context"
	"encoding/json"
	"errors"
	"html"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// repeatFixture is a PoC and a deterministic app: run i reflects the
// query raw when reflects[i], escaped otherwise. Nothing depends on
// timing, so the rate is the same on every machine.
type repeatFixture struct {
	About    string          `json:"about"`
	PoC      json.RawMessage `json:"poc"`
	Reflects []bool          `json:"reflects"`
	Want     Rate            `json:"want"`
}

func loadRepeat(t *testing.T, name string) (repeatFixture, PoC) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "repeat", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var f repeatFixture
	if err := decodeStrict(data, &f); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	var req Request
	if err := decodeStrict(f.PoC, &req); err != nil {
		t.Fatalf("%s poc: %v", name, err)
	}
	return f, mustBuild(t, req)
}

// scripted answers the i-th request like searchApp, raw or escaped as the
// fixture says; past the script it escapes.
func scripted(reflects []bool) app {
	n := 0
	return func(req string, tables map[string]bool) (string, time.Duration) {
		escape := html.EscapeString
		if n < len(reflects) && reflects[n] {
			escape = func(s string) string { return s }
		}
		n++
		return searchApp(escape)(req, tables)
	}
}

// TestRepeatRates: a stable fixture is 5/5, the intermittent one a rate
// between 1 and 4 of 5 (acceptance criterion of #25), and one that never
// reflects 0/5, which does not hold.
func TestRepeatRates(t *testing.T) {
	tests := []struct {
		fixture      string
		holds, flaky bool
	}{
		{"stable", true, false},
		{"intermittent", true, true},
		{"never", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.fixture, func(t *testing.T) {
			f, p := loadRepeat(t, tt.fixture)
			runner := newFake(scripted(f.Reflects))
			rep, err := Repeat(context.Background(), runner, Target{Port: testPort}, p, DefaultRuns)
			if err != nil {
				t.Fatal(err)
			}
			if rep.Rate != f.Want || len(rep.Results) != DefaultRuns || len(runner.sent) != DefaultRuns {
				t.Fatalf("rate %v from %d results and %d runner calls, want %v", rep.Rate, len(rep.Results), len(runner.sent), f.Want)
			}
			if rep.Rate.Holds() != tt.holds || rep.Rate.Intermittent() != tt.flaky {
				t.Errorf("%v: holds %v intermittent %v", rep.Rate, rep.Rate.Holds(), rep.Rate.Intermittent())
			}
			if tt.flaky && (rep.Rate.Verified < 1 || rep.Rate.Verified > 4) {
				t.Errorf("intermittent rate %v is not between 1 and 4 of 5", rep.Rate)
			}
			for i, res := range rep.Results {
				if (res.Outcome == Verified) != f.Reflects[i] {
					t.Errorf("run %d: %s, reflects %v", i+1, res.Outcome, f.Reflects[i])
				}
			}
		})
	}
}

// Protection (#25): no run of 0 holds, whatever the counts claim, so no
// finding is ever verified from a PoC that never verified; a rate outside
// 1 to MaxRuns runs, or with more verified runs than runs, is not valid.
func TestNoVerifiedFromZeroRuns(t *testing.T) {
	for _, r := range []Rate{{0, 5}, {0, 1}, {0, MaxRuns}, {1, 0}, {6, 5}, {-1, 5}, {1, MaxRuns + 1}, {0, 0}} {
		if r.Holds() || r.Intermittent() {
			t.Errorf("rate %+v holds", r)
		}
	}
	for _, r := range []Rate{{1, 5}, {5, 5}, {1, 1}} {
		if !r.Holds() {
			t.Errorf("rate %+v does not hold", r)
		}
	}
	_, p := loadRepeat(t, "never")
	rep, err := Repeat(context.Background(), newFake(always(page("<p>results for &lt;b&gt;</p>"))), Target{Port: testPort}, p, DefaultRuns)
	if err != nil || rep.Rate.Holds() || rep.Rate.Verified != 0 {
		t.Errorf("an app that never reflects: %v, %v", rep.Rate, err)
	}
}

// TestRepeatRefusesBadRuns and stops at a sandbox error: no rate is made
// of the runs before it.
func TestRepeatErrors(t *testing.T) {
	_, p := loadRepeat(t, "stable")
	for _, runs := range []int{0, -1, MaxRuns + 1} {
		runner := newFake(always(page("x")))
		if _, err := Repeat(context.Background(), runner, Target{Port: testPort}, p, runs); !errors.Is(err, ErrInvalid) || len(runner.sent) != 0 {
			t.Errorf("%d runs: %v after %d calls", runs, err, len(runner.sent))
		}
	}
	runner := newFake(always(page("x")))
	runner.err = errors.New("canary aborted the run")
	rep, err := Repeat(context.Background(), runner, Target{Port: testPort}, p, DefaultRuns)
	if err == nil || rep.Rate.Runs != 0 || len(runner.sent) != 1 {
		t.Errorf("sandbox error: %v, rate %v after %d calls", err, rep.Rate, len(runner.sent))
	}
	if _, err := Repeat(context.Background(), runner, Target{Port: testPort}, PoC{}, 1); !errors.Is(err, ErrInvalid) {
		t.Errorf("unbuilt PoC: %v", err)
	}
}
