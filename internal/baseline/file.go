package baseline

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/sneakercreepers/creep/internal/report"
)

// Version is the baseline file format (ADR 0022); a change that breaks
// reading a stored file bumps it.
const Version = 1

// Bounds on a file the scanned repository can hold.
const (
	MaxBytes     = 1 << 20 // the caller reads at most this much
	MaxEntries   = 4096
	MaxDays      = 365 // the furthest expiry `creep accept` writes
	BaselineDays = 90  // the expiry of the entries --baseline-write writes
	maxPathBytes = 4096
)

// clockSlack lets a file written on a clock a day ahead still load: an
// expiry up to MaxDays plus this many days ahead is accepted.
const clockSlack = 1

// ErrInvalid is wrapped by every error about a file's content.
var ErrInvalid = errors.New("invalid baseline file")

// Entry is one finding the gate does not count until Expires (a UTC day,
// report.DateLayout): the first day it no longer suppresses.
type Entry struct {
	Kind        report.SuppressionKind `json:"kind"`
	Fingerprint string                 `json:"fingerprint"`
	Class       string                 `json:"class"`
	Path        string                 `json:"path"`
	Expires     string                 `json:"expires"`
	Reason      string                 `json:"reason,omitempty"`
}

// File is the baseline file.
type File struct {
	Version int     `json:"version"`
	Entries []Entry `json:"entries"`
}

// Day is t's UTC calendar day, the only clock the package compares.
func Day(t time.Time) time.Time {
	y, m, d := t.UTC().Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

// Parse reads a baseline file strictly: one JSON value, no unknown field,
// Version, at most MaxEntries entries, each fully valid. Any fault fails
// the whole file, and errors name the entry and field, never the value.
func Parse(data []byte, today time.Time) (*File, error) {
	if len(data) > MaxBytes {
		return nil, fmt.Errorf("%w: larger than %d bytes", ErrInvalid, MaxBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var f File
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("%w: not the baseline JSON format", ErrInvalid)
	}
	if len(bytes.TrimSpace(data[dec.InputOffset():])) > 0 {
		return nil, fmt.Errorf("%w: trailing data after the baseline", ErrInvalid)
	}
	if f.Version != Version {
		return nil, fmt.Errorf("%w: version %d, want %d", ErrInvalid, f.Version, Version)
	}
	if err := f.check(Day(today)); err != nil {
		return nil, err
	}
	return &f, nil
}

func (f *File) check(today time.Time) error {
	if len(f.Entries) > MaxEntries {
		return fmt.Errorf("%w: %d entries, at most %d", ErrInvalid, len(f.Entries), MaxEntries)
	}
	latest := today.AddDate(0, 0, MaxDays+clockSlack)
	for i, e := range f.Entries {
		if field := e.fault(latest); field != "" {
			return fmt.Errorf("%w: entry %d: %s", ErrInvalid, i+1, field)
		}
	}
	return nil
}

// fault names the first invalid field of e, or "".
func (e Entry) fault(latest time.Time) string {
	switch {
	case e.Kind != report.SuppressBaseline && e.Kind != report.SuppressAccepted:
		return "kind must be baseline or accepted"
	case !report.ValidFingerprint(e.Fingerprint):
		return "fingerprint must be 32 lowercase hex digits"
	case !report.ValidID(e.Class):
		return "class must be a class ID"
	case len(e.Path) > maxPathBytes || !report.ValidPath(e.Path):
		return "path must be a clean repository-relative path"
	case !report.ValidDate(e.Expires):
		return "expires must be a date, YYYY-MM-DD"
	case e.Kind == report.SuppressAccepted && !report.ValidReason(e.Reason), e.Reason != "" && !report.ValidReason(e.Reason):
		return fmt.Sprintf("reason must be one printable line of at most %d bytes (required for accepted)", report.MaxReasonBytes)
	}
	if expires, _ := time.Parse(report.DateLayout, e.Expires); expires.After(latest) {
		return fmt.Sprintf("expires more than %d days ahead", MaxDays)
	}
	return ""
}

// expired reports whether e no longer suppresses on today (a Day).
func (e Entry) expired(today time.Time) bool {
	expires, err := time.Parse(report.DateLayout, e.Expires)
	return err != nil || !today.Before(expires)
}

// Marshal writes f in a fixed order (kind, path, class, expiry,
// fingerprint), so a refreshed baseline diffs only where findings changed.
func (f *File) Marshal() ([]byte, error) {
	out := File{Version: Version, Entries: slices.Clone(f.Entries)}
	if out.Entries == nil {
		out.Entries = []Entry{}
	}
	slices.SortStableFunc(out.Entries, func(a, b Entry) int {
		for _, c := range [][2]string{{string(a.Kind), string(b.Kind)}, {a.Path, b.Path}, {a.Class, b.Class}, {a.Expires, b.Expires}, {a.Fingerprint, b.Fingerprint}} {
			if n := strings.Compare(c[0], c[1]); n != 0 {
				return n
			}
		}
		return 0
	})
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode baseline: %w", err)
	}
	return append(data, '\n'), nil
}
