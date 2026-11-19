package discover

import (
	"crypto/hmac"
	"crypto/sha256"
	_ "embed" // the canary file is data in canary.txt
	"encoding/binary"
	"encoding/hex"
	"slices"
	"strings"
)

// The canary is a small Express router planted in every batch, with an
// entry point and a file sink at lines creep knows (ADR 0017). A model that
// follows the instructions for the batch reports both; one that skipped
// files or obeyed text telling it to stop does not, and the batch is
// incomplete. It holds no repository text.
const (
	tokenPlaceholder = "{{token}}"
	entryMarker      = "{{entry}}"
	sinkMarker       = "{{sink}}"
	// canaryTokenBytes is the token's length before hex: 64 bits, so no
	// repository text holds it by chance, and creep checks anyway.
	canaryTokenBytes = 8
	// canaryAttempts bounds the search for a token the batch does not
	// hold. Failing every attempt means something is wrong; the batch is
	// then not sent and its files are parse_failed.
	canaryAttempts = 8
)

//go:embed canary.txt
var canaryData string

// canary is where the planted entry point and sink are.
type canary struct {
	section int // 0-based file index in the batch
	entry   int // 1-based line
	sink    int // 1-based line
}

// plantCanary inserts the canary section among sections. Its token and
// position come from an HMAC of the batch under the run's seed, so a file
// author cannot predict them, and the same seed and files give the same
// request byte for byte (replay). ok is false when every token tried
// occurs in the batch.
func plantCanary(seed [32]byte, sections []section) ([]section, canary, bool) {
	text := renderBatch(sections)
	for attempt := range canaryAttempts {
		sum := canaryMAC(seed, attempt, text)
		token := hex.EncodeToString(sum[:canaryTokenBytes])
		if strings.Contains(text, token) {
			continue
		}
		lines, c := canaryLines(token)
		slots := uint16(len(sections) + 1)                                  //nolint:gosec // G115: at most MaxFilesPerBatch sections
		pos := int(binary.BigEndian.Uint16(sum[canaryTokenBytes:]) % slots) //nolint:gosec // G115: below slots
		c.section = pos
		planted := section{work: -1, lang: canaryLanguage, lines: lines}
		return slices.Insert(slices.Clone(sections), pos, planted), c, true
	}
	return nil, canary{}, false
}

func canaryMAC(seed [32]byte, attempt int, text string) []byte {
	mac := hmac.New(sha256.New, seed[:])
	mac.Write([]byte("creep discover canary v1"))
	mac.Write([]byte{byte(attempt)}) //nolint:gosec // G115: attempt < canaryAttempts
	mac.Write([]byte(text))
	return mac.Sum(nil)
}

// canaryLines expands the template with token and returns its lines and
// the lines of its entry point and sink.
func canaryLines(token string) ([]string, canary) {
	lines := splitLines(strings.ReplaceAll(canaryData, tokenPlaceholder, token))
	var c canary
	for i, l := range lines {
		if rest, ok := strings.CutPrefix(l, entryMarker); ok {
			lines[i], c.entry = rest, i+1
		}
		if rest, ok := strings.CutPrefix(l, sinkMarker); ok {
			lines[i], c.sink = rest, i+1
		}
	}
	return lines, c
}

// canarySize is the bytes the canary section takes; every token has the
// same length, so it is fixed.
func canarySize() int {
	lines, _ := canaryLines(strings.Repeat("0", 2*canaryTokenBytes))
	return section{lang: canaryLanguage, lines: lines}.size()
}

// found reports whether a holds an entry covering the canary's entry line
// and a sink on its sink line, both in the canary's file.
func (c canary) found(a reply) bool {
	entry := slices.ContainsFunc(a.entries, func(e entryRec) bool {
		return e.file == c.section && e.start <= c.entry && c.entry <= e.end
	})
	sink := slices.ContainsFunc(a.sinks, func(s sinkRec) bool { return s.file == c.section && s.line == c.sink })
	return entry && sink
}
