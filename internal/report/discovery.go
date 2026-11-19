package report

import (
	"fmt"
	"io"
	"strings"
)

// Discovery is what the inventory and model discovery saw (ADR 0017), for
// the text summary and Markdown only. JSON v1 gains nothing (D3), so a
// report read back has none.
type Discovery struct {
	// WholeFiles is how many source files discovery sent whole, redacted
	// (D1): the files of every batch it sent.
	WholeFiles int
	// Inventory counts files per kind and ID, such as language go.
	Inventory []InventoryCount
	// Batches names, per discovery call, why its files are parse_failed:
	// the JSON reason cannot say which cause applied.
	Batches []BatchNote
}

// InventoryCount is how many files the inventory put under one ID.
type InventoryCount struct {
	Kind  string // InventoryLanguage, InventoryManifest or InventoryContainer
	ID    string
	Files int
}

// Inventory kinds.
const (
	InventoryLanguage  = "language"
	InventoryManifest  = "manifest"
	InventoryContainer = "container"
)

// BatchCause is why every file of one discovery batch is parse_failed.
type BatchCause string

// Batch causes.
const (
	CauseCanaryMissed BatchCause = "canary_missed"
	CauseInvalidReply BatchCause = "invalid_reply"
)

// BatchNote is one discovery batch whose files are parse_failed.
type BatchNote struct {
	Batch int // 1-based, in the order discovery sent them
	Files int // repository files in it, the canary not counted
	Cause BatchCause
}

// Text says what the cause means, so nobody looks for a syntax error in a
// file that is fine.
func (n BatchNote) Text() string {
	switch n.Cause {
	case CauseCanaryMissed:
		return fmt.Sprintf("discovery canary not found in batch %d: the model did not follow the instructions for this batch (%d files)", n.Batch, n.Files)
	case CauseInvalidReply:
		return fmt.Sprintf("discovery reply invalid for batch %d: the model's answer broke the schema or named lines outside its files (%d files)", n.Batch, n.Files)
	}
	return fmt.Sprintf("discovery batch %d failed (%d files)", n.Batch, n.Files)
}

func checkDiscovery(d Discovery) error {
	if d.WholeFiles < 0 {
		return fmt.Errorf("%w: discovery whole files %d", ErrInvalid, d.WholeFiles)
	}
	for _, c := range d.Inventory {
		kindOK := c.Kind == InventoryLanguage || c.Kind == InventoryManifest || c.Kind == InventoryContainer
		if !kindOK || !idPattern.MatchString(c.ID) || c.Files < 1 {
			return fmt.Errorf("%w: inventory %q %q %d", ErrInvalid, c.Kind, c.ID, c.Files)
		}
	}
	for _, b := range d.Batches {
		if b.Batch < 1 || b.Files < 0 || b.Cause != CauseCanaryMissed && b.Cause != CauseInvalidReply {
			return fmt.Errorf("%w: discovery batch %d %q", ErrInvalid, b.Batch, b.Cause)
		}
	}
	return nil
}

// writeDiscovery prints the inventory and each failed batch's cause. Every
// value is a count or an ID New checked.
func writeDiscovery(w io.Writer, d Discovery) {
	if len(d.Inventory) == 0 && len(d.Batches) == 0 {
		return
	}
	fmt.Fprint(w, "## Inventory\n\n")
	if len(d.Inventory) > 0 {
		parts := make([]string, len(d.Inventory))
		for i, c := range d.Inventory {
			parts[i] = fmt.Sprintf("%s %s %d", c.Kind, codeSpan(c.ID), c.Files)
		}
		fmt.Fprintf(w, "Files found: %s.\n\n", strings.Join(parts, ", "))
	}
	for _, b := range d.Batches {
		fmt.Fprintf(w, "- %s\n", b.Text())
	}
	if len(d.Batches) > 0 {
		fmt.Fprint(w, "\n")
	}
}

// wholeFilesLine states discovery's whole-file egress in the data-handling
// section (ADR 0017 D1).
func wholeFilesLine(n int) string {
	if n == 0 {
		return ""
	}
	return fmt.Sprintf("Discovery sent %d whole source files, each redacted, to the model; reader requests sent slices.\n\n", n)
}
