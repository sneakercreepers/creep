package report

import (
	"fmt"
	"io"
	"regexp"
	"time"
	"unicode"
	"unicode/utf8"
)

// SuppressionKind says which kind of baseline entry hides a finding from
// the gate (ADR 0022), a closed set.
type SuppressionKind string

// Suppression kinds.
const (
	// SuppressBaseline is an entry `creep scan --baseline-write` wrote for a
	// finding that existed when the baseline was taken.
	SuppressBaseline SuppressionKind = "baseline"
	// SuppressAccepted is an entry `creep accept` wrote, with a reason.
	SuppressAccepted SuppressionKind = "accepted"
)

// DateLayout is the form of every expiry date: a UTC calendar day.
const DateLayout = "2006-01-02"

// MaxReasonBytes bounds an accepted risk's reason.
const MaxReasonBytes = 200

// Suppression is the baseline entry that kept a probable or verified
// finding from tripping the gate. The finding keeps its status and is still
// listed in every format; only the gate skips it. Expires is the first day
// the entry no longer suppresses. Reason is the repository's own text
// (the baseline file is committed there): escape it before printing.
type Suppression struct {
	Kind    SuppressionKind `json:"kind"`
	Expires string          `json:"expires"`
	Reason  string          `json:"reason,omitempty"`
}

// fingerprintPattern is a baseline fingerprint: 128 bits of SHA-256, hex.
var fingerprintPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

// ValidFingerprint reports whether s is a well-formed finding fingerprint.
func ValidFingerprint(s string) bool { return fingerprintPattern.MatchString(s) }

// ValidDate reports whether s is a calendar day in DateLayout, written the
// one way DateLayout writes it.
func ValidDate(s string) bool {
	d, err := time.Parse(DateLayout, s)
	return err == nil && d.Format(DateLayout) == s
}

// ValidReason reports whether s can be an accepted risk's reason: non-blank
// UTF-8 of at most MaxReasonBytes, with no control or format rune (bidi
// included), so it prints as the one line a reviewer read.
func ValidReason(s string) bool {
	if len(s) > MaxReasonBytes || !utf8.ValidString(s) {
		return false
	}
	blank := true
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
		blank = blank && unicode.IsSpace(r)
	}
	return !blank
}

// Suppressed reports whether a baseline entry keeps f from the gate.
func (f Finding) Suppressed() bool { return f.Suppression != nil }

func checkSuppression(f Finding) error {
	if f.Fingerprint != "" && !ValidFingerprint(f.Fingerprint) {
		return fmt.Errorf("%w: finding %s: fingerprint %q", ErrInvalid, f.ID, f.Fingerprint)
	}
	s := f.Suppression
	if s == nil {
		return nil
	}
	gating := f.Status == StatusProbable || f.Status == StatusVerified
	switch {
	case !gating || f.Fingerprint == "":
		// Never on not_evaluated or discarded: only a finding the gate
		// would count can be suppressed, and only by its fingerprint.
		return fmt.Errorf("%w: finding %s: a %s finding without a fingerprint cannot be suppressed", ErrInvalid, f.ID, f.Status)
	case s.Kind != SuppressBaseline && s.Kind != SuppressAccepted:
		return fmt.Errorf("%w: finding %s: suppression kind %q", ErrInvalid, f.ID, s.Kind)
	case !ValidDate(s.Expires):
		return fmt.Errorf("%w: finding %s: suppression expiry %q", ErrInvalid, f.ID, s.Expires)
	case s.Kind == SuppressAccepted && !ValidReason(s.Reason), s.Reason != "" && !ValidReason(s.Reason):
		return fmt.Errorf("%w: finding %s: suppression reason", ErrInvalid, f.ID)
	}
	return nil
}

// Text says what suppresses f, or "" when nothing does. It holds the
// reason as written: escape it before printing.
func (s *Suppression) Text() string {
	switch {
	case s == nil:
		return ""
	case s.Kind == SuppressAccepted:
		return fmt.Sprintf("suppressed: accepted risk until %s: %s", s.Expires, s.Reason)
	}
	return fmt.Sprintf("suppressed: %s until %s", s.Kind, s.Expires)
}

// BaselineUse is how a run used its baseline file (`--baseline`, #27), for
// the text summary, Markdown and SARIF. It holds counts only; JSON states
// the suppressions on each finding. Every entry is either expired, matched
// one finding, or matched none.
type BaselineUse struct {
	On        bool
	Entries   int // entries in the file
	Expired   int // entries on or past their expiry day: they suppress nothing
	Unmatched int // live entries no finding of this run matched
}

func checkBaseline(b BaselineUse, findings []Finding) error {
	suppressed := countSuppressed(findings)
	switch {
	case !b.On && (b != BaselineUse{} || suppressed.all() > 0):
	case b.Entries < 0, b.Expired < 0, b.Unmatched < 0:
	case b.On && suppressed.all()+b.Expired+b.Unmatched != b.Entries:
	default:
		return nil
	}
	return fmt.Errorf("%w: baseline use %+v with %d suppressed findings", ErrInvalid, b, suppressed.all())
}

type suppressedCount struct{ baseline, accepted int }

func (c suppressedCount) all() int { return c.baseline + c.accepted }

func countSuppressed(findings []Finding) suppressedCount {
	var c suppressedCount
	for _, f := range findings {
		switch {
		case f.Suppression == nil:
		case f.Suppression.Kind == SuppressAccepted:
			c.accepted++
		default:
			c.baseline++
		}
	}
	return c
}

// Text is the baseline line, or "" when the run had no baseline. Entries
// that matched nothing are never read as fixed: code the run did not
// evaluate, or an incremental scan left out, can still hold them.
func (b BaselineUse) Text(findings []Finding) string {
	if !b.On {
		return ""
	}
	c := countSuppressed(findings)
	return fmt.Sprintf("baseline: %s suppressed (%d baseline, %s), still listed and not counted by the gate; "+
		"%s nothing; %s matched no finding of this run (not read as fixed)",
		countNoun(c.all(), "finding", "findings"), c.baseline, countNoun(c.accepted, "accepted risk", "accepted risks"),
		countNoun(b.Expired, "expired entry suppresses", "expired entries suppress"), countNoun(b.Unmatched, "live entry", "live entries"))
}

func countNoun(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

// writeSuppressions is Markdown's list of suppressed findings, after the
// findings table, so nothing a baseline hides goes unlisted.
func writeSuppressions(w io.Writer, b BaselineUse, findings []Finding) {
	if !b.On {
		return
	}
	fmt.Fprintf(w, "## Suppressed\n\n**%s.**\n\n", b.Text(findings))
	if countSuppressed(findings).all() == 0 {
		return
	}
	fmt.Fprint(w, "| ID | Class | Location | Kind | Expires | Reason |\n|---|---|---|---|---|---|\n")
	for _, f := range findings {
		if s := f.Suppression; s != nil {
			reason := "none"
			if s.Reason != "" {
				reason = codeSpan(s.Reason)
			}
			fmt.Fprintf(w, "| %s | %s | %s | %s | %s | %s |\n", codeSpan(f.ID), codeSpan(f.Class),
				codeSpan(locationText(f)), statusText(string(s.Kind)), codeSpan(s.Expires), reason)
		}
	}
	fmt.Fprint(w, "\n")
}

func locationText(f Finding) string {
	if f.Line > 0 {
		return fmt.Sprintf("%s:%d", f.Path, f.Line)
	}
	return f.Path
}

// sarifSuppression is SARIF 2.1.0's suppression object: the entry lives
// outside the source (the baseline file), and a reviewer accepted it.
type sarifSuppression struct {
	Kind          string `json:"kind"`
	Status        string `json:"status"`
	Justification string `json:"justification"`
}

func sarifSuppressions(s *Suppression) []sarifSuppression {
	if s == nil {
		return nil
	}
	return []sarifSuppression{{Kind: "external", Status: "accepted", Justification: s.Text()}}
}

// fingerprintKey names creep's fingerprint in SARIF partialFingerprints.
const fingerprintKey = "creepFingerprint/v1"

func sarifFingerprints(f Finding) map[string]string {
	if f.Fingerprint == "" {
		return nil
	}
	return map[string]string{fingerprintKey: f.Fingerprint}
}

func baselineNotifications(text string) []sarifNotification {
	if text == "" {
		return nil
	}
	return []sarifNotification{{Descriptor: sarifDescriptor{ID: "creep/baseline"}, Level: "note", Message: sarifMessage{Text: text}}}
}
