package calibrate

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/sneakercreepers/creep/internal/state"
)

// ClassStability is what --stability scans of one model saw for one class
// (ADR 0024): how many findings they labeled and how many of those were
// unstable discoveries. Many unstable findings say the model is at the
// edge of its ability for the class.
type ClassStability struct {
	Findings int `json:"findings"`
	Unstable int `json:"unstable"`
}

// MaxStabilityFindings bounds each class's counts. Past it both halve, so
// the record keeps its rate, leans to recent scans and never grows.
const MaxStabilityFindings = 256

// stabilityVersion is the record's format; another one is not read.
const stabilityVersion = 1

// stabilityDomain keeps the record's key apart from the calibration's,
// which hashes the same fields without it.
const stabilityDomain = "creep discovery stability v1\x00"

type stabilityRecord struct {
	Version int                      `json:"version"`
	Classes map[Class]ClassStability `json:"classes"`
}

// stabilityKey names the record of the calibration whose key fields are f:
// a model, client, seed, task set or prompt change starts a new record,
// as it starts a new calibration.
func stabilityKey(f cacheKeyFields) string {
	b, err := json.Marshal(f)
	if err != nil {
		panic(err) // strings and integers always marshal
	}
	sum := sha256.Sum256(append([]byte(stabilityDomain), b...))
	return hex.EncodeToString(sum[:])
}

// RecordStability adds one scan's per-class counts to the model's record,
// signed in opts.Store beside its calibration, and returns the new record.
// Only calibrated classes are kept; a count below zero, or more unstable
// findings than findings, is refused. A record that is missing, planted,
// unsigned, malformed or older than MaxAge starts afresh. The caller never
// records a --replay run, so replay neither reads nor changes it.
func RecordStability(opts CacheOptions, seen map[Class]ClassStability) (map[Class]ClassStability, error) {
	if opts.Store == nil || opts.Now == nil || opts.MaxAge <= 0 || opts.Model == nil {
		return nil, fmt.Errorf("%w: store, clock, max age and model are required", ErrOptions)
	}
	if err := checkSeen(seen); err != nil {
		return nil, err
	}
	tasks, err := Generate(opts.Seed)
	if err != nil {
		return nil, err
	}
	want := keyFields(opts, tasks)
	merged, started, err := loadStabilityAt(opts, want)
	if err != nil && !untrusted(err) {
		return nil, fmt.Errorf("stability record: %w", err)
	}
	if merged == nil {
		started = opts.Now().UTC().Truncate(time.Second)
	}
	merged = addStability(merged, seen)
	raw, err := json.Marshal(stabilityRecord{Version: stabilityVersion, Classes: merged})
	if err != nil {
		return nil, fmt.Errorf("stability record: %w", err)
	}
	// The record keeps the time of its first scan, so it expires MaxAge
	// after it started, as a calibration does, however often it is added to.
	if err := opts.Store.SaveCalibration(stabilityKey(want), state.Calibration{At: started, Result: raw}); err != nil {
		return nil, fmt.Errorf("stability record: %w", err)
	}
	return merged, nil
}

func checkSeen(seen map[Class]ClassStability) error {
	for class, c := range seen {
		if !slices.Contains(Classes(), class) || c.Findings < 0 || c.Unstable < 0 || c.Unstable > c.Findings {
			return fmt.Errorf("%w: stability of %q: %+v", ErrOptions, class, c)
		}
	}
	return nil
}

// addStability adds seen to rec, halving a class past the bound.
func addStability(rec, seen map[Class]ClassStability) map[Class]ClassStability {
	out := make(map[Class]ClassStability, len(rec)+len(seen))
	for class, c := range rec {
		out[class] = c
	}
	for class, c := range seen {
		sum := out[class]
		sum.Findings += min(c.Findings, MaxStabilityFindings)
		sum.Unstable += min(c.Unstable, MaxStabilityFindings)
		for sum.Findings > MaxStabilityFindings {
			sum.Findings, sum.Unstable = sum.Findings/2, sum.Unstable/2
		}
		out[class] = sum
	}
	return out
}

// loadStability reads the record for want: nil when there is none, it is
// older than MaxAge or from the future, or it does not decode strictly to
// counts of calibrated classes within the bound. Only an error from the
// store (untrusted, newer version, I/O) is returned.
func loadStability(opts CacheOptions, want cacheKeyFields) (map[Class]ClassStability, error) {
	rec, _, err := loadStabilityAt(opts, want)
	return rec, err
}

// loadStabilityAt is loadStability with the time the record started.
func loadStabilityAt(opts CacheOptions, want cacheKeyFields) (map[Class]ClassStability, time.Time, error) {
	c, ok, err := opts.Store.LoadCalibration(stabilityKey(want))
	if err != nil || !ok {
		return nil, time.Time{}, err
	}
	if age := opts.Now().Sub(c.At); age < 0 || age >= opts.MaxAge {
		return nil, time.Time{}, nil
	}
	var rec stabilityRecord
	dec := json.NewDecoder(bytes.NewReader(c.Result))
	dec.DisallowUnknownFields()
	if dec.Decode(&rec) != nil || dec.More() || rec.Version != stabilityVersion || !validRecord(rec.Classes) {
		return nil, time.Time{}, nil
	}
	return rec.Classes, c.At, nil
}

func validRecord(classes map[Class]ClassStability) bool {
	for class, c := range classes {
		if checkSeen(map[Class]ClassStability{class: c}) != nil || c.Findings > MaxStabilityFindings {
			return false
		}
	}
	return true
}

// stabilityNote is the calibration line's note on the classes whose
// findings were unstable discoveries, in Classes order.
func stabilityNote(rec map[Class]ClassStability) string {
	var parts []string
	for _, class := range Classes() {
		if c := rec[class]; c.Unstable > 0 {
			parts = append(parts, fmt.Sprintf("%s %d/%d", class, c.Unstable, c.Findings))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return " · unstable discoveries: " + strings.Join(parts, ", ")
}
