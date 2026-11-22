package report

import (
	"fmt"
	"io"
)

// Verification is what the sandbox did to verify the findings (ADR 0016,
// #23, #25), for the text summary, Markdown and SARIF only. JSON v1 is
// frozen (ADR 0009), so it gains nothing and a report read back has none.
// It never makes a run incomplete: without verification, findings stay
// probable, which is what a run without a sandbox reports.
type Verification struct {
	Status VerificationStatus
	Reason string // why verification is unavailable, an ID; "" otherwise
	Detail string // the reason's closed detail, an ID or ""
	PoCs   PoCSummary
}

// PoCSummary counts the PoCs a scan ran against the app it built (#25).
// Only an app_built verification has one.
type PoCSummary struct {
	Ran          int // findings whose PoC ran all its runs
	Verified     int // of Ran: verified in every run
	Intermittent int // of Ran: verified in some runs only
	// NotRun counts probable findings of a class with a PoC template that
	// got no completed run: no valid PoC from the model, the scan deadline
	// or a sandbox error. They stay probable.
	NotRun int
}

// VerificationStatus is how far verification got.
type VerificationStatus string

// Verification statuses. The zero value says nothing: sandbox.enabled is
// false, as before the sandbox existed.
const (
	VerificationOff         VerificationStatus = ""
	VerificationAppBuilt    VerificationStatus = "app_built"   // built offline; PoCs ran against it (PoCs)
	VerificationUnavailable VerificationStatus = "unavailable" // no runtime, no build or no app: Reason says why
)

// verificationReasons is the closed set of reasons verification is
// unavailable: the sandbox's build reasons (sandbox.BuildReasons; a CLI
// test keeps both in step) and the scan's own.
var verificationReasons = map[string]bool{
	"no_build_file": true, "compose_refused": true, "dockerfile_refused": true, "context_refused": true,
	"base_image_missing": true, "build_failed": true, "build_timeout": true, "image_refused": true, "runtime_error": true,
	"no_runtime": true, "not_checked": true, "sandbox_error": true, "interrupted": true, "budget": true,
	"no_port": true, "start_failed": true,
}

// ValidVerificationReason reports whether reason is in the closed set, so
// the CLI can map anything else before New refuses it.
func ValidVerificationReason(reason string) bool { return verificationReasons[reason] }

func checkVerification(v Verification) error {
	if verificationValid(v) {
		return nil
	}
	return fmt.Errorf("%w: verification %q, reason %q, detail %q, PoCs %+v", ErrInvalid, v.Status, v.Reason, v.Detail, v.PoCs)
}

func verificationValid(v Verification) bool {
	switch v.Status {
	case VerificationOff:
		return v == Verification{}
	case VerificationAppBuilt:
		return v.Reason == "" && v.Detail == "" && v.PoCs.valid()
	case VerificationUnavailable:
		return v.PoCs == (PoCSummary{}) && verificationReasons[v.Reason] && (v.Detail == "" || idPattern.MatchString(v.Detail))
	}
	return false
}

func (p PoCSummary) valid() bool {
	return p.Ran >= 0 && p.Verified >= 0 && p.Intermittent >= 0 && p.NotRun >= 0 && p.Verified+p.Intermittent <= p.Ran
}

// Text is the one-line outcome, "" when verification is off. Every value
// in it is an ID or a count New checked.
func (v Verification) Text() string {
	switch v.Status {
	case VerificationAppBuilt:
		return "the app was built offline in the sandbox; " + v.PoCs.text()
	case VerificationUnavailable:
		return "verification unavailable (" + v.cause() + "); findings stay probable"
	}
	return ""
}

func (p PoCSummary) text() string {
	if p.Ran == 0 && p.NotRun == 0 {
		return "no probable finding has a PoC template, so findings stay probable"
	}
	return fmt.Sprintf("PoCs ran for %d findings: %d verified in every run, %d intermittent, %d not reproduced; "+
		"%d got no PoC run; findings not verified stay probable",
		p.Ran, p.Verified, p.Intermittent, p.Ran-p.Verified-p.Intermittent, p.NotRun)
}

func (v Verification) cause() string {
	if v.Detail == "" {
		return v.Reason
	}
	return v.Reason + ": " + v.Detail
}

// writeVerification is Markdown's verification section.
func writeVerification(w io.Writer, v Verification) {
	switch v.Status {
	case VerificationAppBuilt:
		fmt.Fprintf(w, "## Verification\n\nThe app was built offline in the sandbox: %s.\n\n", v.PoCs.text())
	case VerificationUnavailable:
		fmt.Fprintf(w, "## Verification\n\n**Verification unavailable** (%s): every finding stays probable.\n\n", codeSpan(v.cause()))
	}
}

// verificationNotifications is SARIF's note on the outcome.
func verificationNotifications(v Verification) []sarifNotification {
	if v.Status == VerificationOff {
		return nil
	}
	return []sarifNotification{{
		Descriptor: sarifDescriptor{ID: "creep/verification/" + string(v.Status)},
		Level:      "note",
		Message:    sarifMessage{Text: v.Text()},
	}}
}
