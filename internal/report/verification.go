package report

import (
	"fmt"
	"io"
)

// Verification is what the sandbox did to verify the findings (ADR 0016,
// #23), for the text summary, Markdown and SARIF only. JSON v1 is frozen
// (ADR 0009), so it gains nothing and a report read back has none. It
// never makes a run incomplete: without verification, findings stay
// probable, which is what a run without a sandbox reports.
type Verification struct {
	Status VerificationStatus
	Reason string // why verification is unavailable, an ID; "" otherwise
	Detail string // the reason's closed detail, an ID or ""
}

// VerificationStatus is how far verification got.
type VerificationStatus string

// Verification statuses. The zero value says nothing: sandbox.enabled is
// false, as before the sandbox existed.
const (
	VerificationOff         VerificationStatus = ""
	VerificationAppBuilt    VerificationStatus = "app_built"   // built offline; no PoC runs yet (#24, #25)
	VerificationUnavailable VerificationStatus = "unavailable" // no runtime, or no build: Reason says why
)

// verificationReasons is the closed set of reasons verification is
// unavailable: the sandbox's build reasons (sandbox.BuildReasons; a CLI
// test keeps both in step) and the scan's own.
var verificationReasons = map[string]bool{
	"no_build_file": true, "compose_refused": true, "dockerfile_refused": true, "context_refused": true,
	"base_image_missing": true, "build_failed": true, "build_timeout": true, "image_refused": true, "runtime_error": true,
	"no_runtime": true, "not_checked": true, "sandbox_error": true, "interrupted": true, "budget": true,
}

// ValidVerificationReason reports whether reason is in the closed set, so
// the CLI can map anything else before New refuses it.
func ValidVerificationReason(reason string) bool { return verificationReasons[reason] }

func checkVerification(v Verification) error {
	switch v.Status {
	case VerificationOff, VerificationAppBuilt:
		if v.Reason == "" && v.Detail == "" {
			return nil
		}
	case VerificationUnavailable:
		if verificationReasons[v.Reason] && (v.Detail == "" || idPattern.MatchString(v.Detail)) {
			return nil
		}
	}
	return fmt.Errorf("%w: verification %q, reason %q, detail %q", ErrInvalid, v.Status, v.Reason, v.Detail)
}

// Text is the one-line outcome, "" when verification is off. Every value
// in it is an ID New checked.
func (v Verification) Text() string {
	switch v.Status {
	case VerificationAppBuilt:
		return "the app was built offline in the sandbox; PoC verification is not built yet (#24, #25), so findings stay probable"
	case VerificationUnavailable:
		return "verification unavailable (" + v.cause() + "); findings stay probable"
	}
	return ""
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
		fmt.Fprintf(w, "## Verification\n\nThe app was built offline in the sandbox. PoC verification is not built yet, so every finding stays probable.\n\n")
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
