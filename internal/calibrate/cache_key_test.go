package calibrate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sneakercreepers/creep/internal/models"
	"github.com/sneakercreepers/creep/internal/state"
)

// modelWithOptions is the cache tests' model with edit applied to its
// options.
func modelWithOptions(t *testing.T, e *cacheEnv, edit func(*models.Options)) *models.HTTP {
	t.Helper()
	opts := models.Options{
		Contract: "openai", Endpoint: "https://models.invalid/v1", Model: "replay-model",
		Structured: models.StructuredSchema, MaxOutputTokens: 64, Retries: 1, Send: e.model.send,
	}
	edit(&opts)
	h, err := models.NewHTTP(opts)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// A client option that changes what the model answers is part of the key
// (#180): changing it in config measures the model again instead of reusing
// the old tier for up to MaxAge.
func TestCacheKeyedOnClientSettings(t *testing.T) {
	tests := []struct {
		name string
		edit func(*models.Options)
	}{
		{"structured output", func(o *models.Options) { o.Structured = models.StructuredPrompt }},
		{"max output tokens", func(o *models.Options) { o.MaxOutputTokens = 128 }},
		{"retries", func(o *models.Options) { o.Retries = 2 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newCacheEnv(t)
			e.run(t, e.options(t, calibrated))
			opts := e.options(t, calibrated.Add(time.Hour))
			opts.Model = modelWithOptions(t, e, tt.edit)
			if got, calls := e.run(t, opts); got.Cached || calls == 0 {
				t.Fatalf("cached=%v with %d calls; want a new run", got.Cached, calls)
			}
			if again, calls := e.run(t, opts); !again.Cached || calls != 0 {
				t.Fatalf("second lookup cached=%v with %d calls; want a hit", again.Cached, calls)
			}
		})
	}
}

// legacyKeyFields is the key before #180, without the client settings.
type legacyKeyFields struct {
	Model         models.Identity `json:"model"`
	Seed          uint64          `json:"seed"`
	TaskSet       string          `json:"task_set"`
	PromptVersion int             `json:"prompt_version"`
}

func legacyKey(t *testing.T, f cacheKeyFields) string {
	t.Helper()
	b, err := json.Marshal(legacyKeyFields{Model: f.Model, Seed: f.Seed, TaskSet: f.TaskSet, PromptVersion: f.PromptVersion})
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// An entry stored by a creep before #180 is never read: under its own key
// it is never looked up, and copied to the new key's file its signed key
// does not match, so it is ErrCorrupt. Either way the model is measured
// again and the old file is left alone.
func TestOldCacheKeysNeverRead(t *testing.T) {
	tests := []struct {
		name      string
		atNewName bool
	}{
		{"under the old key", false},
		{"copied to the new key's file", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newCacheEnv(t)
			first, _ := e.run(t, e.options(t, calibrated))
			newPath := e.cacheFile(t)
			old := legacyKey(t, e.keyFields(t))
			if old == strings.TrimSuffix(filepath.Base(newPath), ".json") {
				t.Fatal("the client settings did not change the key")
			}
			e.saveRaw(t, old, first.Result)
			oldPath := filepath.Join(e.dir, "calibrations", old+".json")
			oldLine, err := os.ReadFile(oldPath)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(newPath); err != nil {
				t.Fatal(err)
			}
			if tt.atNewName {
				writeCache(t, newPath, oldLine)
			}
			later := calibrated.Add(time.Hour)
			if got, calls := e.run(t, e.options(t, later)); got.Cached || calls == 0 || !got.At.Equal(later) {
				t.Fatalf("cached=%v calls=%d at=%v; want a new run", got.Cached, calls, got.At)
			}
			if after, err := os.ReadFile(oldPath); err != nil || string(after) != string(oldLine) {
				t.Fatalf("old entry changed: %v", err)
			}
		})
	}
}

// v05TaskSet is the task-set hash of seed 1 under v0.5's Python and
// JavaScript templates (its TestGenerateGolden), and v05PromptVersion its
// prompts.
const (
	v05TaskSet       = "0320e1388fbfc57ee8d26dd165659c348f3fc361651cb86e2c0aa07143a98983"
	v05PromptVersion = 1
)

// Acceptance (#358): a calibration cached by v0.5 is never served after
// the upgrade. Under its own key it is never looked up; its result signed
// under the new key still names the old task set and prompts, so it is
// refused. Either way the model is measured again on the neutral set.
func TestV05CacheNotServed(t *testing.T) {
	for _, atNewKey := range []bool{false, true} {
		e := newCacheEnv(t)
		first, _ := e.run(t, e.options(t, calibrated))
		newPath := e.cacheFile(t)
		if err := os.Remove(newPath); err != nil {
			t.Fatal(err)
		}
		old := e.keyFields(t)
		old.TaskSet, old.PromptVersion = v05TaskSet, v05PromptVersion
		stale := first.Result
		stale.TaskSet, stale.PromptVersion = v05TaskSet, v05PromptVersion
		key := cacheKey(old)
		if atNewKey {
			key = strings.TrimSuffix(filepath.Base(newPath), ".json")
		}
		e.saveRaw(t, key, stale)
		later := calibrated.Add(time.Hour)
		got, calls := e.run(t, e.options(t, later))
		if got.Cached || calls == 0 || got.TaskSet == v05TaskSet || got.PromptVersion != PromptVersion {
			t.Fatalf("new key %v: cached=%v calls=%d task set %s v%d; want a new run on the neutral set",
				atNewKey, got.Cached, calls, got.TaskSet, got.PromptVersion)
		}
	}
}

func (e *cacheEnv) keyFields(t *testing.T) cacheKeyFields {
	t.Helper()
	tasks := mustGenerate(t, cacheSeed)
	m := newModel(t, e.model.send)
	return cacheKeyFields{
		Model: m.Identity(), Client: m.Settings(), Seed: cacheSeed,
		TaskSet: taskSetHash(tasks), PromptVersion: PromptVersion,
	}
}

func (e *cacheEnv) saveRaw(t *testing.T, key string, r Result) {
	t.Helper()
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.store.SaveCalibration(key, state.Calibration{At: calibrated, Result: raw}); err != nil {
		t.Fatal(err)
	}
}

// A calibrations/ directory that is a link fails closed before any model
// call, with or without --recalibrate, and names the directory to remove.
func TestLinkedCacheDirFailsBeforeCalls(t *testing.T) {
	for _, recalibrate := range []bool{false, true} {
		t.Run("recalibrate="+strconv.FormatBool(recalibrate), func(t *testing.T) {
			e := newCacheEnv(t)
			dir := filepath.Join(e.dir, "calibrations")
			if err := os.Symlink(t.TempDir(), dir); err != nil {
				t.Skipf("symlink: %v", err)
			}
			opts := e.options(t, calibrated)
			opts.Recalibrate = recalibrate
			_, err := RunCached(context.Background(), opts)
			if !errors.Is(err, state.ErrUnsafePath) || !strings.Contains(err.Error(), strconv.Quote(dir)) {
				t.Fatalf("err = %v; want ErrUnsafePath naming %q", err, dir)
			}
			if len(e.model.calls) != 0 {
				t.Fatalf("%d model calls before failing", len(e.model.calls))
			}
		})
	}
}

// consistent accepts only what runContextProbes can produce, so a cached
// stop reason is never misread.
func TestContextCheckConsistent(t *testing.T) {
	tests := []struct {
		name string
		c    ContextCheck
		ok   bool
	}{
		{"every size", ContextCheck{EffectiveBytes: 128 << 10}, true},
		{"400 at 8 KiB", ContextCheck{StoppedAt: 8 << 10, Stop: ContextStopStatus, Status: 400}, true},
		{"413 at 32 KiB", ContextCheck{EffectiveBytes: 8 << 10, StoppedAt: 32 << 10, Stop: ContextStopStatus, Status: 413}, true},
		{"wrong at 128 KiB", ContextCheck{EffectiveBytes: 32 << 10, StoppedAt: 128 << 10, Stop: ContextStopWrongAnswer}, true},
		{"budget at 8 KiB", ContextCheck{StoppedAt: 8 << 10, Stop: ContextStopBudget}, true},
		{"pre-#174 result with no stop", ContextCheck{EffectiveBytes: 32 << 10}, false},
		{"stop skips a size", ContextCheck{StoppedAt: 32 << 10, Stop: ContextStopWrongAnswer}, false},
		{"stop past the largest size", ContextCheck{EffectiveBytes: 128 << 10, StoppedAt: 256 << 10, Stop: ContextStopBudget}, false},
		{"size not probed", ContextCheck{EffectiveBytes: 16 << 10, StoppedAt: 32 << 10, Stop: ContextStopBudget}, false},
		{"status 500", ContextCheck{StoppedAt: 8 << 10, Stop: ContextStopStatus, Status: 500}, false},
		{"status without a status stop", ContextCheck{StoppedAt: 8 << 10, Stop: ContextStopWrongAnswer, Status: 400}, false},
		{"unknown stop", ContextCheck{StoppedAt: 8 << 10, Stop: "tired"}, false},
		{"status with no stop", ContextCheck{EffectiveBytes: 128 << 10, Status: 400}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.c.consistent(); got != tt.ok {
				t.Errorf("consistent(%+v) = %v, want %v", tt.c, got, tt.ok)
			}
		})
	}
}

// The header names the context probe that stopped and why, and is silent
// when every size was answered.
func TestHeaderContextNote(t *testing.T) {
	tests := []struct {
		name string
		c    ContextCheck
		want string
	}{
		{"every size", ContextCheck{EffectiveBytes: 128 << 10}, ""},
		{"400 at 8 KiB", ContextCheck{StoppedAt: 8 << 10, Stop: ContextStopStatus, Status: 400}, " · context 0 KiB (8 KiB probe: HTTP 400)"},
		{"wrong at 128 KiB", ContextCheck{EffectiveBytes: 32 << 10, StoppedAt: 128 << 10, Stop: ContextStopWrongAnswer}, " · context 32 KiB (128 KiB probe: wrong_answer)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := Calibration{Result: Result{Context: tt.c, Fitness: Fitness{Fit: true}}, At: calibrated}
			if h := c.Header(); !strings.HasSuffix(h, "prompts v0)"+tt.want) {
				t.Errorf("header %q does not end with %q", h, tt.want)
			}
		})
	}
}
