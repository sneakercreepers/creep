package baseline

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"time"

	"github.com/sneakercreepers/creep/internal/report"
)

// matchKey is what an entry and a finding must share exactly.
type matchKey struct{ fingerprint, class, path string }

func (e Entry) key() matchKey { return matchKey{e.Fingerprint, e.Class, e.Path} }

func findingKey(f report.Finding) matchKey { return matchKey{f.Fingerprint, f.Class, f.Path} }

// gating reports whether f is a finding the gate counts and a baseline
// may therefore suppress: probable or verified, with a fingerprint.
func gating(f report.Finding) bool {
	return (f.Status == report.StatusProbable || f.Status == report.StatusVerified) && f.Fingerprint != ""
}

// Apply sets the Suppression of each finding a live entry of b matches and
// returns the counts for the report. Each entry suppresses at most one
// finding, so two identical sinks need two entries; findings are matched
// in the order given, entries in file order. Any Suppression already on a
// finding is replaced.
func Apply(findings []report.Finding, b *File, today time.Time) report.BaselineUse {
	day := Day(today)
	use := report.BaselineUse{On: true, Entries: len(b.Entries)}
	live := map[matchKey][]Entry{}
	for _, e := range b.Entries {
		if e.expired(day) {
			use.Expired++
			continue
		}
		live[e.key()] = append(live[e.key()], e)
	}
	for i := range findings {
		f := &findings[i]
		f.Suppression = nil
		entries := live[findingKey(*f)]
		if !gating(*f) || len(entries) == 0 {
			continue
		}
		e := entries[0]
		live[findingKey(*f)] = entries[1:]
		f.Suppression = &report.Suppression{Kind: e.Kind, Expires: e.Expires, Reason: e.Reason}
	}
	for _, entries := range live {
		use.Unmatched += len(entries)
	}
	return use
}

// Writable refuses a report a baseline must not be taken from: an
// incomplete run, or one that left any file out but vendor, generated and
// minified ones (an incremental scan's unchanged files included). Its
// missing findings would read as gone, and their entries would be dropped.
func Writable(rep *report.Report) error {
	if rep.Run.Incomplete {
		return fmt.Errorf("the run is incomplete (%s): a baseline from it would drop what it did not evaluate", rep.Run.Reason)
	}
	left := 0
	for _, n := range rep.Coverage.NotEvaluated {
		switch n.Reason {
		case report.SkipVendor, report.SkipGenerated, report.SkipMinified:
		default:
			left++
		}
	}
	if left > 0 {
		return fmt.Errorf("the run did not evaluate %d files in full: a baseline from it would drop their findings", left)
	}
	return nil
}

// Refresh is the baseline --baseline-write writes after a run: b's live
// accepted risks unchanged, and one baseline entry, expiring BaselineDays
// after today, for every probable or verified finding no accepted risk
// suppresses. Expired entries and old baseline entries are dropped.
func Refresh(b *File, findings []report.Finding, today time.Time) (*File, error) {
	day := Day(today)
	out := &File{Version: Version}
	for _, e := range b.Entries {
		if e.Kind == report.SuppressAccepted && !e.expired(day) {
			out.Entries = append(out.Entries, e)
		}
	}
	expires := day.AddDate(0, 0, BaselineDays).Format(report.DateLayout)
	for _, f := range findings {
		if !gating(f) || (f.Suppression != nil && f.Suppression.Kind == report.SuppressAccepted) {
			continue
		}
		out.Entries = append(out.Entries, Entry{
			Kind: report.SuppressBaseline, Fingerprint: f.Fingerprint, Class: f.Class, Path: f.Path, Expires: expires,
		})
	}
	return out, out.fits()
}

func (f *File) fits() error {
	if len(f.Entries) > MaxEntries {
		return fmt.Errorf("%w: %d entries, at most %d", ErrInvalid, len(f.Entries), MaxEntries)
	}
	return nil
}

// ErrNotAcceptable means a finding cannot become an accepted risk.
var ErrNotAcceptable = errors.New("cannot accept")

// Accept returns b with f accepted as a risk for days days from today,
// for reason. It replaces one baseline entry for f, if b has one, so the
// finding is not counted twice. Only a probable or verified finding with a
// fingerprint can be accepted, never a not-evaluated one.
func Accept(b *File, f report.Finding, days int, reason string, today time.Time) (*File, error) {
	switch {
	case !gating(f):
		return nil, fmt.Errorf("%w: finding %s is %s without a fingerprint; only a probable or verified finding can be accepted", ErrNotAcceptable, f.ID, f.Status)
	case days < 1 || days > MaxDays:
		return nil, fmt.Errorf("%w: the expiry must be 1 to %d days ahead", ErrNotAcceptable, MaxDays)
	case !report.ValidReason(reason):
		return nil, fmt.Errorf("%w: the reason must be one printable line of at most %d bytes", ErrNotAcceptable, report.MaxReasonBytes)
	}
	out := &File{Version: Version, Entries: slices.Clone(b.Entries)}
	if i := slices.IndexFunc(out.Entries, func(e Entry) bool {
		return e.Kind == report.SuppressBaseline && e.key() == findingKey(f)
	}); i >= 0 {
		out.Entries = slices.Delete(out.Entries, i, i+1)
	}
	out.Entries = append(out.Entries, Entry{
		Kind: report.SuppressAccepted, Fingerprint: f.Fingerprint, Class: f.Class, Path: f.Path,
		Expires: Day(today).AddDate(0, 0, days).Format(report.DateLayout), Reason: reason,
	})
	return out, out.fits()
}

// daysPattern is `creep accept --expires`: a number of days, "90d".
var daysPattern = regexp.MustCompile(`^[1-9][0-9]{0,2}d$`)

// ParseDays reads an --expires value: 1d to MaxDays d.
func ParseDays(s string) (int, error) {
	if !daysPattern.MatchString(s) {
		return 0, fmt.Errorf("%w: --expires must be a number of days, such as 90d", ErrNotAcceptable)
	}
	n, err := strconv.Atoi(s[:len(s)-1])
	if err != nil || n > MaxDays {
		return 0, fmt.Errorf("%w: --expires must be 1d to %dd", ErrNotAcceptable, MaxDays)
	}
	return n, nil
}
