package calibrate

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sneakercreepers/creep/internal/models"
	"github.com/sneakercreepers/creep/internal/state"
)

// #37: a --stability scan's per-class counts accumulate in a signed record
// beside the model's calibration, and the next calibration line names the
// classes whose findings were unstable discoveries.
func TestStabilityFeedsCalibration(t *testing.T) {
	e := newCacheEnv(t)
	opts := e.options(t, calibrated)
	if c, _ := e.run(t, opts); c.Stability != nil {
		t.Fatalf("stability %+v before any stability scan", c.Stability)
	}
	scans := []map[Class]ClassStability{
		{ClassSQLi: {Findings: 3, Unstable: 1}},
		{ClassSQLi: {Findings: 2, Unstable: 1}, ClassSSRF: {Findings: 1}},
	}
	for _, seen := range scans {
		if _, err := RecordStability(opts, seen); err != nil {
			t.Fatal(err)
		}
	}
	c, calls := e.run(t, opts)
	if calls != 0 || !c.Cached {
		t.Fatalf("the record must not cost a calibration: %d calls, cached %v", calls, c.Cached)
	}
	want := map[Class]ClassStability{ClassSQLi: {Findings: 5, Unstable: 2}, ClassSSRF: {Findings: 1}}
	if len(c.Stability) != len(want) || c.Stability[ClassSQLi] != want[ClassSQLi] || c.Stability[ClassSSRF] != want[ClassSSRF] {
		t.Fatalf("stability = %+v, want %+v", c.Stability, want)
	}
	if h := c.Header(); !strings.HasSuffix(h, " · unstable discoveries: sqli 2/5") {
		t.Errorf("header %q does not name the unstable class", h)
	}
}

// The record's key is the calibration's fields under its own domain: the
// same model, client, seed, task set and prompts find it; another model or
// client setting does not, and it never answers as a calibration.
func TestStabilityKeyFollowsCalibration(t *testing.T) {
	e := newCacheEnv(t)
	opts := e.options(t, calibrated)
	if _, err := RecordStability(opts, map[Class]ClassStability{ClassSSRF: {Findings: 2, Unstable: 2}}); err != nil {
		t.Fatal(err)
	}
	tasks, err := Generate(cacheSeed)
	if err != nil {
		t.Fatal(err)
	}
	f := keyFields(opts, tasks)
	if stabilityKey(f) == cacheKey(f) {
		t.Fatal("the stability record shares the calibration's key")
	}
	if _, ok, err := e.store.LoadCalibration(cacheKey(f)); ok || err != nil {
		t.Fatalf("a stability record answered as a calibration: %v %v", ok, err)
	}
	other := opts
	other.Model, err = models.NewHTTP(models.Options{
		Contract: "openai", Endpoint: "https://models.invalid/v1", Model: "replay-model",
		Structured: models.StructuredSchema, MaxOutputTokens: 128, Retries: 1, Send: e.model.send,
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := loadStability(other, keyFields(other, tasks))
	if err != nil || got != nil {
		t.Errorf("another client setting read the record: %+v, %v", got, err)
	}
	if got, err := loadStability(opts, f); err != nil || got[ClassSSRF].Unstable != 2 {
		t.Errorf("the same key lost the record: %+v, %v", got, err)
	}
}

// The record stays bounded: past MaxStabilityFindings a class halves, so
// its rate holds and its counts never grow.
func TestStabilityRecordBounded(t *testing.T) {
	e := newCacheEnv(t)
	opts := e.options(t, calibrated)
	var rec map[Class]ClassStability
	var err error
	for range 10 {
		rec, err = RecordStability(opts, map[Class]ClassStability{ClassSQLi: {Findings: 100, Unstable: 50}})
		if err != nil {
			t.Fatal(err)
		}
		if c := rec[ClassSQLi]; c.Findings > MaxStabilityFindings || c.Unstable > c.Findings {
			t.Fatalf("record %+v over the bound", c)
		}
	}
	if c := rec[ClassSQLi]; c.Unstable*2 != c.Findings {
		t.Errorf("record %+v lost its rate", c)
	}
	huge := map[Class]ClassStability{ClassSSRF: {Findings: 1 << 30, Unstable: 1 << 29}}
	if rec, err = RecordStability(opts, huge); err != nil || rec[ClassSSRF].Findings > MaxStabilityFindings {
		t.Errorf("one huge scan: %+v, %v", rec[ClassSSRF], err)
	}
}

// Counts no scan makes are refused, and a record creep cannot trust
// (another user's, expired, from the future, malformed) starts afresh
// instead of being added to.
func TestStabilityRecordRefuses(t *testing.T) {
	e := newCacheEnv(t)
	opts := e.options(t, calibrated)
	for name, seen := range map[string]map[Class]ClassStability{
		"unknown class":            {"xss": {Findings: 1}},
		"negative":                 {ClassSQLi: {Findings: -1}},
		"more unstable than found": {ClassSQLi: {Findings: 1, Unstable: 2}},
	} {
		if _, err := RecordStability(opts, seen); !errors.Is(err, ErrOptions) {
			t.Errorf("%s: err = %v, want ErrOptions", name, err)
		}
	}
	tasks, err := Generate(cacheSeed)
	if err != nil {
		t.Fatal(err)
	}
	key := stabilityKey(keyFields(opts, tasks))
	one := map[Class]ClassStability{ClassSQLi: {Findings: 1, Unstable: 1}}
	tests := []struct {
		name  string
		plant func(t *testing.T)
		now   time.Time
	}{
		{"another user's", func(t *testing.T) {
			foreign := opts
			foreign.Store = openCache(t, e.dir, bytes.Repeat([]byte{0x24}, state.SecretBytes))
			if _, err := RecordStability(foreign, map[Class]ClassStability{ClassSQLi: {Findings: 200, Unstable: 200}}); err != nil {
				t.Fatal(err)
			}
		}, calibrated},
		{"expired", func(*testing.T) {}, calibrated.Add(cacheMaxAge)},
		{"from the future", func(*testing.T) {}, calibrated.Add(-time.Hour)},
		{"malformed", func(t *testing.T) {
			bad := state.Calibration{At: calibrated, Result: []byte(`{"version":1,"classes":{"sqli":{"findings":9,"unstable":9}},"extra":1}`)}
			if err := e.store.SaveCalibration(key, bad); err != nil {
				t.Fatal(err)
			}
		}, calibrated},
		{"over the bound", func(t *testing.T) {
			bad := state.Calibration{At: calibrated, Result: []byte(`{"version":1,"classes":{"sqli":{"findings":9999,"unstable":9}}}`)}
			if err := e.store.SaveCalibration(key, bad); err != nil {
				t.Fatal(err)
			}
		}, calibrated},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := RecordStability(opts, map[Class]ClassStability{ClassSQLi: {Findings: 5, Unstable: 5}}); err != nil {
				t.Fatal(err)
			}
			tt.plant(t)
			later := opts
			later.Now = func() time.Time { return tt.now }
			rec, err := RecordStability(later, one)
			if err != nil || len(rec) != 1 || rec[ClassSQLi] != one[ClassSQLi] {
				t.Errorf("record = %+v, %v; want a fresh one", rec, err)
			}
		})
	}
}
