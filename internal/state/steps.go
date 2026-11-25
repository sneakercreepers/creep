package state

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Step IDs a scan records in its run state (#335, ADR 0032). Each is an ID
// or a digest, never repository text. Only the creep build that wrote a run
// reads its steps (a resume refuses a run whose header names another
// version), so this grammar is not a cross-version contract.
const (
	StepFiles = "files:" // the digest of the walked files and what the scan can read of them
	StepTier  = "tier:"  // the calibrated tier
	// StepCache is a recorded model reply or discovery seed:
	// cache:<key digest>:<reply digest>, so a resume serves only the exact
	// reply the run got, never one a later scan recorded under the key.
	StepCache = "cache:"
	// StepTime is time:<ms>: the scan time spent, persisted while no other
	// step is recorded (sandbox builds, PoC runs, scanners), so a resume
	// gets back at most the time since the last persisted step.
	StepTime = "time:"
)

// digestHex is the length of each digest in a cache step: 128 bits each,
// so the step fits the 128-character ID.
const digestHex = 32

// Digest names the cache entry k in a step without holding any text.
func (k Key) Digest() string {
	h := sha256.New()
	for _, part := range []string{k.ContentHash, k.Model, k.PromptVersion} {
		h.Write([]byte(part + "\x00"))
	}
	return hex.EncodeToString(h.Sum(nil))[:digestHex]
}

// CacheStep is the step that records reply as k's answer.
func CacheStep(k Key, reply []byte) string {
	return StepCache + k.Digest() + ":" + replyDigest(reply)
}

// TimeStep is the step that persists spent scan time.
func TimeStep(spent time.Duration) string {
	return StepTime + strconv.FormatInt(max(spent.Milliseconds(), 0), 10)
}

func replyDigest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])[:digestHex]
}

// Finished is what a run had finished before a resume: its steps, the
// reply digest of each recorded cache key, and the scan time it spent.
type Finished struct {
	steps   []string
	replies map[string]string // key digest -> digest of the reply the run got
	// owed are the cache keys recorded after the tier step: a resume asks
	// for every one of them before any step the run had not reached, since
	// the pipeline sends them in that order. Calibration's keys, recorded
	// before the tier, are not owed: a resume reads the calibration from
	// its cache and never asks them.
	owed  map[string]bool
	spent time.Duration
}

// NewFinished reads what sum's run had finished.
func NewFinished(sum Summary) Finished {
	f := Finished{steps: sum.Steps, replies: map[string]string{}, owed: map[string]bool{}, spent: sum.Elapsed}
	tiered := false
	for _, step := range sum.Steps {
		tiered = tiered || strings.HasPrefix(step, StepTier)
		key, reply, ok := strings.Cut(strings.TrimPrefix(step, StepCache), ":")
		if !ok || !strings.HasPrefix(step, StepCache) {
			continue
		}
		f.replies[key] = reply // the cache holds the last reply recorded under key
		if tiered {
			f.owed[key] = true
		}
	}
	return f
}

// Len is the number of finished steps.
func (f Finished) Len() int { return len(f.steps) }

// Spent is the scan time the run had spent (budget.max_seconds).
func (f Finished) Spent() time.Duration { return f.spent }

// Step returns the value of the first finished step with prefix.
func (f Finished) Step(prefix string) (string, bool) {
	for _, step := range f.steps {
		if v, ok := strings.CutPrefix(step, prefix); ok {
			return v, true
		}
	}
	return "", false
}

// Matches reports whether reply is the reply the run got for the finished
// cache step k.
func (f Finished) Matches(k Key, reply []byte) bool {
	want, ok := f.replies[k.Digest()]
	return ok && want == replyDigest(reply)
}

// IsFinished reports whether k is a finished cache step.
func (f Finished) IsFinished(k Key) bool {
	_, ok := f.replies[k.Digest()]
	return ok
}

// Owed returns a fresh set of the cache keys (by digest) a resume must
// serve before it may send anything new.
func (f Finished) Owed() map[string]bool {
	owed := make(map[string]bool, len(f.owed))
	for k := range f.owed {
		owed[k] = true
	}
	return owed
}

// headerDomain keeps a header digest apart from every signed line.
var headerDomain = []byte("creep header v1\x00")

// HeaderDigest is the keyed digest (HMAC-SHA256 with the per-user state
// secret) of parts, each length-prefixed so no two lists collide, for a
// run header (#335). Equal settings give equal digests for this user, and
// a header read from a shared .creep cannot be reversed by guessing
// well-known values such as endpoints or model names (v0.4 review A11).
func (s *Store) HeaderDigest(parts ...string) (string, error) {
	if !s.key.set() {
		return "", errNoKey
	}
	m := hmac.New(sha256.New, s.key.b)
	m.Write(headerDomain)
	for _, p := range parts {
		fmt.Fprintf(m, "%d:%s,", len(p), p)
	}
	return hex.EncodeToString(m.Sum(nil)), nil
}
