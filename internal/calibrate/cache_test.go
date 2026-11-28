package calibrate

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/sneakercreepers/creep/internal/models"
	"github.com/sneakercreepers/creep/internal/state"
)

const cacheSeed = 1

var (
	cacheSecret = bytes.Repeat([]byte{0x42}, state.SecretBytes)
	calibrated  = time.Date(2026, 11, 14, 9, 30, 0, 0, time.UTC)
	cacheMaxAge = 30 * 24 * time.Hour
)

// cacheEnv is a cache directory plus a model that answers every call
// correctly and counts the calls.
type cacheEnv struct {
	dir   string
	store *state.Store
	model *replayer
	o     oracle
}

func newCacheEnv(t *testing.T) *cacheEnv {
	t.Helper()
	dir := t.TempDir()
	o := newOracle(t, cacheSeed)
	return &cacheEnv{dir: dir, store: openCache(t, dir, cacheSecret), model: answering(o.answer), o: o}
}

func openCache(t *testing.T, dir string, secret []byte) *state.Store {
	t.Helper()
	s, err := state.OpenWithSecret(dir, secret)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func (e *cacheEnv) options(t *testing.T, now time.Time) CacheOptions {
	t.Helper()
	return CacheOptions{
		Options: testOptions(t, cacheSeed, e.model.send), Store: e.store,
		MaxAge: cacheMaxAge, Now: func() time.Time { return now },
	}
}

func (e *cacheEnv) run(t *testing.T, opts CacheOptions) (Calibration, int) {
	t.Helper()
	before := len(e.model.calls)
	c, err := RunCached(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	return c, len(e.model.calls) - before
}

// cacheFile returns the only calibration file in the store.
func (e *cacheEnv) cacheFile(t *testing.T) string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(e.dir, "calibrations", "*.json"))
	if err != nil || len(files) != 1 {
		t.Fatalf("calibration files = %v, %v; want one", files, err)
	}
	return files[0]
}

// The 30-day window: reused strictly inside it, refreshed at and after its
// end, and never trusted from a time later than now.
func TestCacheExpiry(t *testing.T) {
	tests := []struct {
		name   string
		now    time.Time
		reused bool
	}{
		{"same instant", calibrated, true},
		{"one second before expiry", calibrated.Add(cacheMaxAge - time.Second), true},
		{"exactly at expiry", calibrated.Add(cacheMaxAge), false},
		{"after expiry", calibrated.Add(cacheMaxAge + time.Hour), false},
		{"clock moved back", calibrated.Add(-time.Second), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newCacheEnv(t)
			first, calls := e.run(t, e.options(t, calibrated))
			if first.Cached || calls == 0 || !first.At.Equal(calibrated) {
				t.Fatalf("first run: cached=%v calls=%d at=%v; want a fresh run at %v", first.Cached, calls, first.At, calibrated)
			}
			got, calls := e.run(t, e.options(t, tt.now))
			if got.Cached != tt.reused || (calls == 0) != tt.reused {
				t.Fatalf("cached=%v with %d calls; want reused=%v", got.Cached, calls, tt.reused)
			}
			if tt.reused && (!got.At.Equal(calibrated) || got.Tier != first.Tier || got.Overall != first.Overall) {
				t.Fatalf("reused %+v; want the first result from %v", got, calibrated)
			}
			if !tt.reused && !got.At.Equal(tt.now.UTC().Truncate(time.Second)) {
				t.Fatalf("refreshed at %v; want %v", got.At, tt.now)
			}
		})
	}
}

// A different model, endpoint, contract or seed never reuses a result.
func TestCacheKeyedOnModelAndSeed(t *testing.T) {
	tests := []struct {
		name   string
		change func(t *testing.T, e *cacheEnv, o *CacheOptions)
	}{
		{"model name", func(t *testing.T, e *cacheEnv, o *CacheOptions) {
			o.Model = modelWith(t, e, "openai", "https://models.invalid/v1", "replay-model-2025")
		}},
		{"endpoint", func(t *testing.T, e *cacheEnv, o *CacheOptions) {
			o.Model = modelWith(t, e, "openai", "https://other.invalid/v1", "replay-model")
		}},
		{"seed", func(t *testing.T, e *cacheEnv, o *CacheOptions) {
			o.Seed = cacheSeed + 1
			e.model.next = answering(newOracle(t, o.Seed).answer).next
		}},
		{"recalibrate", func(_ *testing.T, _ *cacheEnv, o *CacheOptions) { o.Recalibrate = true }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newCacheEnv(t)
			e.run(t, e.options(t, calibrated))
			opts := e.options(t, calibrated.Add(time.Hour))
			tt.change(t, e, &opts)
			got, calls := e.run(t, opts)
			if got.Cached || calls == 0 {
				t.Fatalf("cached=%v with %d calls; want a new run", got.Cached, calls)
			}
			// The new result is cached in turn.
			opts.Recalibrate = false
			if again, calls := e.run(t, opts); !again.Cached || calls != 0 {
				t.Fatalf("second lookup cached=%v with %d calls; want a hit", again.Cached, calls)
			}
		})
	}
}

func modelWith(t *testing.T, e *cacheEnv, contract, endpoint, name string) *models.HTTP {
	t.Helper()
	h, err := models.NewHTTP(models.Options{
		Contract: contract, Endpoint: endpoint, Model: name,
		Structured: models.StructuredSchema, MaxOutputTokens: 64, Retries: 1, Send: e.model.send,
	})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// A cache file that is damaged, planted or describes something else is never
// trusted: the model is calibrated again and the file replaced.
func TestUntrustedCacheRecalibrates(t *testing.T) {
	tests := []struct {
		name   string
		damage func(t *testing.T, e *cacheEnv, path string)
	}{
		{"garbage", func(t *testing.T, _ *cacheEnv, path string) { writeCache(t, path, []byte("not json\n")) }},
		{"truncated", func(t *testing.T, _ *cacheEnv, path string) {
			b, _ := os.ReadFile(path)
			writeCache(t, path, b[:len(b)/2])
		}},
		{"planted by another user", func(t *testing.T, e *cacheEnv, path string) {
			b, _ := os.ReadFile(path)
			writeCache(t, path, resign(t, b, bytes.Repeat([]byte{0x01}, state.SecretBytes), nil))
		}},
		{"tier raised", func(t *testing.T, _ *cacheEnv, path string) {
			b, _ := os.ReadFile(path)
			writeCache(t, path, resign(t, b, cacheSecret, func(s string) string {
				if strings.Contains(s, `"tier":"L"`) {
					return strings.Replace(s, `"tier":"L"`, `"tier":"S"`, 1)
				}
				return regexpReplace(s, `"tier":"[SM]"`, `"tier":"L"`)
			}))
		}},
		{"other task set", func(t *testing.T, _ *cacheEnv, path string) {
			b, _ := os.ReadFile(path)
			writeCache(t, path, resign(t, b, cacheSecret, func(s string) string {
				return regexpReplace(s, `"task_set":"[0-9a-f]+"`, `"task_set":"00"`)
			}))
		}},
		{"context stop forged", func(t *testing.T, _ *cacheEnv, path string) {
			b, _ := os.ReadFile(path)
			writeCache(t, path, resign(t, b, cacheSecret, func(s string) string {
				return regexpReplace(s, `"effective_bytes":131072`, `"effective_bytes":131072,"status":400`)
			}))
		}},
		// #363: a verdict the counts do not give, counts that do not fit,
		// and an entry from before the fitness floor are all misses.
		{"fitness forged", func(t *testing.T, _ *cacheEnv, path string) {
			b, _ := os.ReadFile(path)
			writeCache(t, path, resign(t, b, cacheSecret, func(s string) string {
				return strings.Replace(s, `"fitness":{"fit":true`, `"fitness":{"fit":false,"reason":"below_chance"`, 1)
			}))
		}},
		{"safe twins forged", func(t *testing.T, _ *cacheEnv, path string) {
			b, _ := os.ReadFile(path)
			writeCache(t, path, resign(t, b, cacheSecret, func(s string) string {
				return strings.Replace(s, `"safe_flagged":0`, `"safe_flagged":99`, 1)
			}))
		}},
		{"entry from before the fitness floor", func(t *testing.T, _ *cacheEnv, path string) {
			b, _ := os.ReadFile(path)
			writeCache(t, path, resign(t, b, cacheSecret, func(s string) string {
				s = regexpReplace(s, `,"fitness":\{"fit":true,"planned":\{[^}]*\}\}`, "")
				return regexpReplace(s, `,"safe_twins":\d+,"safe_flagged":\d+`, "")
			}))
		}},
		{"unknown result field", func(t *testing.T, _ *cacheEnv, path string) {
			b, _ := os.ReadFile(path)
			writeCache(t, path, resign(t, b, cacheSecret, func(s string) string {
				return strings.Replace(s, `"result":{`, `"result":{"trusted":true,`, 1)
			}))
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newCacheEnv(t)
			e.run(t, e.options(t, calibrated))
			path := e.cacheFile(t)
			tt.damage(t, e, path)
			later := calibrated.Add(time.Hour)
			got, calls := e.run(t, e.options(t, later))
			if got.Cached || calls == 0 || !got.At.Equal(later) {
				t.Fatalf("cached=%v calls=%d at=%v; want a new run", got.Cached, calls, got.At)
			}
			if again, calls := e.run(t, e.options(t, later)); !again.Cached || calls != 0 || again.Tier != got.Tier {
				t.Fatalf("after replacing, cached=%v calls=%d; want a hit", again.Cached, calls)
			}
		})
	}
}

// A file written by a newer creep fails closed instead of being overwritten,
// unless --recalibrate asks for that.
func TestNewerCacheVersionFailsClosed(t *testing.T) {
	e := newCacheEnv(t)
	e.run(t, e.options(t, calibrated))
	path := e.cacheFile(t)
	b, _ := os.ReadFile(path)
	writeCache(t, path, resign(t, b, cacheSecret, func(s string) string {
		return strings.Replace(s, `{"v":1,`, `{"v":2,`, 1)
	}))
	before := len(e.model.calls)
	_, err := RunCached(context.Background(), e.options(t, calibrated))
	if !errors.Is(err, state.ErrUnsupportedVersion) || len(e.model.calls) != before {
		t.Fatalf("err = %v after %d calls; want ErrUnsupportedVersion and no call", err, len(e.model.calls)-before)
	}
	opts := e.options(t, calibrated)
	opts.Recalibrate = true
	if got, calls := e.run(t, opts); got.Cached || calls == 0 {
		t.Fatalf("--recalibrate: cached=%v calls=%d; want a new run", got.Cached, calls)
	}
}

func TestRunCachedFailures(t *testing.T) {
	tests := []struct {
		name   string
		change func(t *testing.T, e *cacheEnv, o *CacheOptions)
		want   error
	}{
		{"no store", func(_ *testing.T, _ *cacheEnv, o *CacheOptions) { o.Store = nil }, ErrOptions},
		{"no clock", func(_ *testing.T, _ *cacheEnv, o *CacheOptions) { o.Now = nil }, ErrOptions},
		{"no max age", func(_ *testing.T, _ *cacheEnv, o *CacheOptions) { o.MaxAge = 0 }, ErrOptions},
		{"no model", func(_ *testing.T, _ *cacheEnv, o *CacheOptions) { o.Model = nil }, ErrOptions},
		{"no redactor", func(_ *testing.T, _ *cacheEnv, o *CacheOptions) { o.Redactor = nil }, ErrOptions},
		{"model fails", func(t *testing.T, _ *cacheEnv, o *CacheOptions) { o.Model = newModel(t, contextSend) }, nil},
		{"cache dir not writable", func(t *testing.T, e *cacheEnv, _ *CacheOptions) {
			writeCache(t, filepath.Join(e.dir, "calibrations"), []byte("a file, not a directory"))
		}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newCacheEnv(t)
			opts := e.options(t, calibrated)
			tt.change(t, e, &opts)
			c, err := RunCached(context.Background(), opts)
			if err == nil || (tt.want != nil && !errors.Is(err, tt.want)) || c.Tier != "" {
				t.Fatalf("RunCached = %+v, %v; want error %v and no calibration", c, err, tt.want)
			}
			if files, _ := filepath.Glob(filepath.Join(e.dir, "calibrations", "*.json")); len(files) != 0 {
				t.Fatalf("failed run left %v", files)
			}
		})
	}
}

func TestHeader(t *testing.T) {
	e := newCacheEnv(t)
	c, _ := e.run(t, e.options(t, calibrated.Add(23*time.Hour)))
	h := c.Header()
	for _, want := range []string{`model "replay-model"`, "tier " + string(c.Tier), "calibrated 2026-11-15", "seed 1", "task set " + c.TaskSet[:12], "prompts v2"} {
		if !strings.Contains(h, want) {
			t.Errorf("header %q lacks %q", h, want)
		}
	}
	c.Model.Model = "evil\n# injected"
	if strings.Contains(c.Header(), "\n") {
		t.Errorf("header %q holds a raw newline from the model name", c.Header())
	}
}

func writeCache(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil { //nolint:gosec // G703: the test plants files in its own temp cache dir on purpose
		t.Fatal(err)
	}
}

// resign edits a stored calibration line and signs it again with secret, as
// internal/state does: HMAC-SHA256 over the domain and the line without its
// mac field. It lets a test plant a file whose MAC is valid for the user.
func resign(t *testing.T, line, secret []byte, edit func(string) string) []byte {
	t.Helper()
	s := strings.TrimSuffix(string(line), "\n")
	i := strings.LastIndex(s, `,"mac":"`)
	if i < 0 {
		t.Fatalf("no mac in %q", s)
	}
	body := s[:i] + "}"
	if edit != nil {
		body = edit(body)
	}
	m := hmac.New(sha256.New, secret)
	m.Write([]byte("creep calibration v1\x00"))
	m.Write([]byte(body))
	return []byte(body[:len(body)-1] + `,"mac":"` + hex.EncodeToString(m.Sum(nil)) + "\"}\n")
}

func regexpReplace(s, pattern, repl string) string {
	return regexp.MustCompile(pattern).ReplaceAllLiteralString(s, repl)
}
