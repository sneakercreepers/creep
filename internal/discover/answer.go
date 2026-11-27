package discover

import (
	"bytes"
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
// planning. Numbers are pointers so a missing or null key, which models
// does not refuse in prompt mode, is told apart from 0 and refused.
type EntryProposal struct {
	File  *int   `json:"file"`
	Start *int   `json:"start"`
	End   *int   `json:"end"`
	Kind  string `json:"kind"`
}

// SinkProposal is one sink line in file File; Entry is an index into
// Answer.Entries whose File is the same, or -1.
type SinkProposal struct {
	File  *int   `json:"file"`
	Line  *int   `json:"line"`
	Kind  string `json:"kind"`
	Entry *int   `json:"entry"`
}

// AuthProposal is a span holding an auth check. It may only widen the
// reader's slice: it never sets Authenticated and never skips a sink.
type AuthProposal struct {
	File  *int `json:"file"`
	Start *int `json:"start"`
	End   *int `json:"end"`
}

// reply is an Answer with every required number present: what batch.go
// works on once Validate has passed.
type reply struct {
	entries []entryRec
	sinks   []sinkRec
	auth    []authRec
}

type entryRec struct {
	file, start, end int
	kind             string
}

type sinkRec struct {
	file, line, entry int
	kind              string
}

type authRec struct{ file, start, end int }

var errMissingKey = errors.New("every entry, sink and auth item needs all its keys, none null")

// reply converts a, refusing any missing or null number.
func (a *Answer) reply() (reply, error) {
	if a.Entries == nil || a.Sinks == nil || a.Auth == nil {
		return reply{}, errors.New("entries, sinks and auth must be arrays")
	}
	var r reply
	for _, e := range a.Entries {
		if e.File == nil || e.Start == nil || e.End == nil {
			return reply{}, errMissingKey
		}
		r.entries = append(r.entries, entryRec{*e.File, *e.Start, *e.End, e.Kind})
	}
	for _, s := range a.Sinks {
		if s.File == nil || s.Line == nil || s.Entry == nil {
			return reply{}, errMissingKey
		}
		r.sinks = append(r.sinks, sinkRec{*s.File, *s.Line, *s.Entry, s.Kind})
	}
	for _, s := range a.Auth {
		if s.File == nil || s.Start == nil || s.End == nil {
			return reply{}, errMissingKey
		}
		r.auth = append(r.auth, authRec{*s.File, *s.Start, *s.End})
	}
	return r, nil
}

// Validate checks what decoding cannot: required keys, enums, ranges,
// entry links and the per-file caps. Bounds against the batch are checked
// later (inBounds). Messages state the rule and never quote a value,
// because they go back into the prompt.
func (a *Answer) Validate() error {
	r, err := a.reply()
	if err != nil {
		return err
	}
	return r.validate()
}

func (r reply) validate() error {
	for _, e := range r.entries {
		if !validFile(e.file) || !validRange(e.start, e.end) || !slices.Contains(entryKindNames, e.kind) {
			return errors.New("each entry needs a file index, 1 <= start <= end and a kind the schema lists")
		}
	}
	for _, s := range r.sinks {
		if _, ok := sinkKindByName(s.kind); !ok || !validFile(s.file) || !validRange(s.line, s.line) {
			return errors.New("each sink needs a file index, a line from 1 and a kind the schema lists")
		}
		if s.entry != noEntry && (s.entry < 0 || s.entry >= len(r.entries) || r.entries[s.entry].file != s.file) {
			return errors.New("each sink entry must be -1 or the index of an entry in the same file")
		}
	}
	for _, s := range r.auth {
		if !validFile(s.file) || !validRange(s.start, s.end) {
			return errors.New("each auth span needs a file index and 1 <= start <= end")
		}
	}
	return r.checkCaps()
}

// checkCaps refuses a file over a per-file cap.
func (r reply) checkCaps() error {
	var entries, sinks, auth [maxFiles]int
	for _, e := range r.entries {
		entries[e.file]++
	}
	for _, s := range r.sinks {
		sinks[s.file]++
	}
	for _, s := range r.auth {
		auth[s.file]++
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
// Properties go out in reasoning order (file, start, end, kind; file,
// line, kind, entry), the order a constrained decoder makes the model
// write them: from a Go map json.Marshal would sort them and the model
// would pick "end" before "start" (#362).
func Schema() json.RawMessage {
	line := map[string]any{"type": "integer", "minimum": 1, "maximum": MaxLine}
	file := map[string]any{"type": "integer", "minimum": 0, "maximum": maxFiles - 1}
	entry := closedObject(props{{"file", file}, {"start", line}, {"end", line}, {"kind", enum(entryKindNames)}})
	sink := closedObject(props{
		{"file", file}, {"line", line}, {"kind", enum(sinkKindNames())},
		{"entry", map[string]any{"type": "integer", "minimum": noEntry, "maximum": maxFiles*MaxEntriesPerFile - 1}},
	})
	auth := closedObject(props{{"file", file}, {"start", line}, {"end", line}})
	root := closedObject(props{
		{"entries", array(entry, maxFiles*MaxEntriesPerFile)},
		{"sinks", array(sink, maxFiles*MaxSinksPerFile)},
		{"auth", array(auth, maxFiles*MaxAuthPerFile)},
	})
	out, err := json.Marshal(root)
	if err != nil {
		panic(err) // maps of strings, numbers and slices always marshal
	}
	return out
}

// prop is one schema property; props keep their order when marshaled.
type prop struct {
	name   string
	schema any
}

type props []prop

func (p props) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, kv := range p {
		if i > 0 {
			b.WriteByte(',')
		}
		k, err := json.Marshal(kv.name)
		if err != nil {
			return nil, err
		}
		v, err := json.Marshal(kv.schema)
		if err != nil {
			return nil, err
		}
		b.Write(k)
		b.WriteByte(':')
		b.Write(v)
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

// closedObject requires every property, in the order p lists them.
func closedObject(p props) map[string]any {
	required := make([]string, len(p))
	for i, kv := range p {
		required[i] = kv.name
	}
	return map[string]any{
		"type": "object", "properties": p,
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
