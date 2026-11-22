package baseline

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

// fingerprintDomain versions the hash: changing what goes in it changes
// every fingerprint, which needs a new domain and an ADR 0022 amendment.
const fingerprintDomain = "creep-fingerprint-v1"

// Fingerprint is a finding's identity across runs: the first 128 bits of a
// SHA-256 over the class, the path and the anchor, each length-prefixed so
// no two inputs share a hash by concatenation.
func Fingerprint(class, path, anchor string) string {
	h := sha256.New()
	for _, part := range []string{fingerprintDomain, class, path, anchor} {
		fmt.Fprintf(h, "%d:%s", len(part), part)
	}
	return hex.EncodeToString(h.Sum(nil))[:32]
}

// markerNumber is a redaction marker's run counter. Markers are numbered
// in the order a run meets values, so the same line reads <SECRET_X_1> in
// one run and <SECRET_X_3> in another; the anchor keeps only the label.
var markerNumber = regexp.MustCompile(`(<(?:SECRET|PII)_[A-Z0-9_]+?)_[0-9]+>`)

// SinkAnchor is the anchor of a finding the reader decided: its sink line as
// redact.File wrote it (reader.Slice.Sink), with marker numbers dropped and
// spacing collapsed, so reindenting the line keeps the fingerprint.
func SinkAnchor(redactedLine string) string {
	line := markerNumber.ReplaceAllString(redactedLine, "$1>")
	return "code:" + strings.Join(strings.Fields(line), " ")
}

// ScannerAnchor is the anchor of an optional scanner's finding: the
// runner's line-free rule key (scanrun.Finding.Anchor), never the
// scanner's text, so a secret gitleaks found is never hashed.
func ScannerAnchor(key string) string { return "scanner:" + key }
