package discover

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
)

const (
	// MaxFilesPerBatch caps the repository files in one call; the canary
	// is one more file.
	MaxFilesPerBatch = 8
	// Per-file caps (ADR 0017). A file at a cap is marked truncated; one
	// over a cap makes the reply invalid.
	MaxEntriesPerFile = 256
	MaxSinksPerFile   = 1024
	MaxAuthPerFile    = 256
	// MaxLine caps a cited line number, as in reader.
	MaxLine = 999999
	// maxFiles is how many file indexes a batch has: its files and the
	// canary, numbered 0 to maxFiles-1. The grammar's file rule is one digit.
	maxFiles = MaxFilesPerBatch + 1
	// noEntry is the sink entry index for "no proposed entry point".
	noEntry = -1
)

// Answer is the model's reply (ADR 0017 discovery schema): a closed struct
// of file indexes creep assigned, line numbers and enums, with no free
// text. models.Complete refuses unknown, duplicate and case-variant keys
// and trailing text, then runs Validate. Arrays are required, so a missing
// one is told apart from an empty one.
type Answer struct {
	Entries []EntryProposal `json:"entries"`
	Sinks   []SinkProposal  `json:"sinks"`
	Auth    []AuthProposal  `json:"auth"`
}

// EntryProposal is one entry point in file File. Kind never changes
// planning.
type EntryProposal struct {
	File  int    `json:"file"`
	Start int    `json:"start"`
	End   int    `json:"end"`
	Kind  string `json:"kind"`
}

// SinkProposal is one sink line in file File; Entry is an index into
// Answer.Entries whose File is the same, or -1.
type SinkProposal struct {
	File  int    `json:"file"`
	Line  int    `json:"line"`
	Kind  string `json:"kind"`
	Entry int    `json:"entry"`
}

// AuthProposal is a span holding an auth check. It may only widen the
// reader's slice: it never sets Authenticated and never skips a sink.
type AuthProposal struct {
	File  int `json:"file"`
	Start int `json:"start"`
	End   int `json:"end"`
}

// Validate checks what decoding cannot: enums, ranges, entry links and the
// per-file caps. Bounds against the batch are checked later (inBounds).
// Messages state the rule and never quote a value, because they go back
// into the prompt.
func (a *Answer) Validate() error {
	if a.Entries == nil || a.Sinks == nil || a.Auth == nil {
		return errors.New("entries, sinks and auth must be arrays")
	}
	for _, e := range a.Entries {
		if !validFile(e.File) || !validRange(e.Start, e.End) || !slices.Contains(entryKindNames, e.Kind) {
			return errors.New("each entry needs a file index, 1 <= start <= end and a kind the schema lists")
		}
	}
	for _, s := range a.Sinks {
		if _, ok := sinkKindByName(s.Kind); !ok || !validFile(s.File) || !validRange(s.Line, s.Line) {
			return errors.New("each sink needs a file index, a line from 1 and a kind the schema lists")
		}
		if s.Entry != noEntry && (s.Entry < 0 || s.Entry >= len(a.Entries) || a.Entries[s.Entry].File != s.File) {
			return errors.New("each sink entry must be -1 or the index of an entry in the same file")
		}
	}
	for _, s := range a.Auth {
		if !validFile(s.File) || !validRange(s.Start, s.End) {
			return errors.New("each auth span needs a file index and 1 <= start <= end")
		}
	}
	return a.checkCaps()
}

// checkCaps refuses a file over a per-file cap.
func (a *Answer) checkCaps() error {
	var entries, sinks, auth [maxFiles]int
	for _, e := range a.Entries {
		entries[e.File]++
	}
	for _, s := range a.Sinks {
		sinks[s.File]++
	}
	for _, s := range a.Auth {
		auth[s.File]++
	}
	for f := range maxFiles {
		if entries[f] > MaxEntriesPerFile || sinks[f] > MaxSinksPerFile || auth[f] > MaxAuthPerFile {
			return fmt.Errorf("a file may have at most %d entries, %d sinks and %d auth spans", MaxEntriesPerFile, MaxSinksPerFile, MaxAuthPerFile)
		}
	}
	return nil
}

func validFile(f int) bool { return f >= 0 && f < maxFiles }

func validRange(start, end int) bool {
	return start >= 1 && end >= start && end <= MaxLine
}

// Schema is Answer's JSON schema, closed at every level for strict mode.
func Schema() json.RawMessage {
	line := map[string]any{"type": "integer", "minimum": 1, "maximum": MaxLine}
	file := map[string]any{"type": "integer", "minimum": 0, "maximum": maxFiles - 1}
	entry := closedObject(map[string]any{
		"file": file, "start": line, "end": line, "kind": enum(entryKindNames),
	}, "file", "start", "end", "kind")
	sink := closedObject(map[string]any{
		"file": file, "line": line, "kind": enum(sinkKindNames()),
		"entry": map[string]any{"type": "integer", "minimum": noEntry, "maximum": maxFiles*MaxEntriesPerFile - 1},
	}, "file", "line", "kind", "entry")
	auth := closedObject(map[string]any{"file": file, "start": line, "end": line}, "file", "start", "end")
	root := closedObject(map[string]any{
		"entries": array(entry, maxFiles*MaxEntriesPerFile),
		"sinks":   array(sink, maxFiles*MaxSinksPerFile),
		"auth":    array(auth, maxFiles*MaxAuthPerFile),
	}, "entries", "sinks", "auth")
	out, err := json.Marshal(root)
	if err != nil {
		panic(err) // maps of strings, numbers and slices always marshal
	}
	return out
}

func closedObject(props map[string]any, required ...string) map[string]any {
	return map[string]any{
		"type": "object", "properties": props,
		"required": required, "additionalProperties": false,
	}
}

func array(items any, maxItems int) map[string]any {
	return map[string]any{"type": "array", "maxItems": maxItems, "items": items}
}

func enum(values []string) map[string]any {
	return map[string]any{"type": "string", "enum": values}
}

func sinkKindNames() []string {
	var out []string
	for _, k := range sinkKinds {
		out = append(out, k.name)
	}
	return out
}

// Grammar is Answer's GBNF grammar. It cannot express the caps, start <=
// end or entry links; Validate still checks those.
func Grammar() string {
	obj := func(fields ...string) string {
		return `"{" ws ` + strings.Join(fields, ` ws "," ws `) + ` ws "}"`
	}
	field := func(name, rule string) string { return `"\"` + name + `\":" ws ` + rule }
	list := func(rule string) string { return `"[" ws (` + rule + ` (ws "," ws ` + rule + `)*)? ws "]"` }
	return `root ::= ` + obj(field("entries", list("entry")), field("sinks", list("sink")), field("auth", list("auth"))) + "\n" +
		`entry ::= ` + obj(field("file", "fileno"), field("start", "line"), field("end", "line"), field("kind", "entrykind")) + "\n" +
		`sink ::= ` + obj(field("file", "fileno"), field("line", "line"), field("kind", "sinkkind"), field("entry", "index")) + "\n" +
		`auth ::= ` + obj(field("file", "fileno"), field("start", "line"), field("end", "line")) + "\n" +
		`entrykind ::= ` + alternatives(entryKindNames) + "\n" +
		`sinkkind ::= ` + alternatives(sinkKindNames()) + "\n" +
		`fileno ::= [0-8]` + "\n" +
		`index ::= "-1" | "0" | [1-9] [0-9]? [0-9]? [0-9]?` + "\n" +
		`line ::= [1-9] [0-9]? [0-9]? [0-9]? [0-9]? [0-9]?` + "\n" +
		`ws ::= [ \t\n]*` + "\n"
}

func alternatives(values []string) string {
	quoted := make([]string, len(values))
	for i, v := range values {
		quoted[i] = `"\"` + v + `\""`
	}
	return strings.Join(quoted, " | ")
}
