package baseline

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	if err := checkKeys(data); err != nil {
		return nil, err
	}
	if f.Version != Version {
		return nil, fmt.Errorf("%w: version %d, want %d", ErrInvalid, f.Version, Version)
	}
	if err := f.check(Day(today)); err != nil {
		return nil, err
	}
	return &f, nil
}

// fieldNames are the only keys a baseline file holds, spelled exactly.
// encoding/json matches a key whatever its case and keeps the last of a
// repeated key, so "Expires" or a second "expires" would decide what a
// reviewer reading the diff did not see.
var fieldNames = map[string]bool{
	"version": true, "entries": true, "kind": true, "fingerprint": true,
	"class": true, "path": true, "expires": true, "reason": true,
}

// keyFrame is one open object or array while checkKeys walks the tokens.
type keyFrame struct {
	seen    map[string]bool // keys met so far; nil for an array
	wantKey bool            // the next string is a key
}

// checkKeys refuses a key that is not in fieldNames as spelled there, or
// that repeats in one object. data is one valid JSON value (Parse decoded
// it first), so only the keys are checked here.
func checkKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	var stack []*keyFrame
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("%w: not the baseline JSON format", ErrInvalid)
		}
		var top *keyFrame
		if len(stack) > 0 {
			top = stack[len(stack)-1]
		}
		if top != nil && top.wantKey && tok != json.Delim('}') {
			if err := top.key(tok); err != nil {
				return err
			}
			continue
		}
		stack = step(stack, top, tok)
	}
}

// key records tok, an object's key, and refuses it when it is unknown as
// spelled or repeated.
func (k *keyFrame) key(tok json.Token) error {
	name, _ := tok.(string)
	if !fieldNames[name] || k.seen[name] {
		return fmt.Errorf("%w: a key is unknown as spelled, or repeated in one object", ErrInvalid)
	}
	k.seen[name] = true
	k.wantKey = false
	return nil
}

// step moves the walk past tok, a value or a closing delimiter.
func step(stack []*keyFrame, top *keyFrame, tok json.Token) []*keyFrame {
	if top != nil && top.seen != nil {
		top.wantKey = true // after this value, the object's next key
	}
	switch tok {
	case json.Delim('{'):
		return append(stack, &keyFrame{seen: map[string]bool{}, wantKey: true})
	case json.Delim('['):
		return append(stack, &keyFrame{})
	case json.Delim('}'), json.Delim(']'):
		return stack[:len(stack)-1]
	}
	return stack
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
