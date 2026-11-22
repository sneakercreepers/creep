package recipe

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"

	"github.com/sneakercreepers/creep/internal/reader"
)

// Version is the only recipe format version this build reads.
const Version = 1

// Limits of the recipe format, mirrored in docs/schemas/recipe-v1.json
// (TestSchemaMatchesLimits). Every one is checked before any model call.
const (
	MaxFileBytes    = 64 << 10 // the whole recipe file
	MaxIDBytes      = 63
	MaxAppliesTo    = 16
	MaxExtBytes     = 11 // "." and up to 10 letters or digits
	MaxSignatures   = 16 // sources, and sinks, each
	MinSignature    = 2
	MaxSignature    = 64
	MaxFixtureBytes = 8 << 10
	MaxFixtureLines = 200
	MaxPoCBytes     = 8 << 10
	MaxKeyBytes     = 32
)

// ErrInvalid means the recipe is refused before any model call: it breaks
// the format, a limit or a rule. Its messages name the field, never quote
// a value, since a recipe is untrusted text.
var ErrInvalid = errors.New("recipe refused")

// Recipe is one recipe file: data, never code. The struct is the closed
// schema; Parse refuses anything else.
type Recipe struct {
	Version   int      `json:"version"`
	ID        string   `json:"id"`
	Class     string   `json:"class"`
	AppliesTo []string `json:"applies_to"`
	Sources   []string `json:"sources"`
	Sinks     []string `json:"sinks"`
	// Hint is untrusted text for the reader only (ADR 0025).
	Hint string `json:"hint"`
	// PoC is a verify.Request (ADR 0019), or absent. recipe may not import
	// verify (layer 6), so the caller checks it through a PoCCheck.
	PoC      json.RawMessage `json:"poc,omitempty"`
	Fixtures Fixtures        `json:"fixtures"`
}

// Fixtures are the two programs a recipe must get right to load.
type Fixtures struct {
	Vulnerable Fixture `json:"vulnerable"`
	Safe       Fixture `json:"safe"`
}

// Fixture is a small program and the 1-based lines of its source and sink.
type Fixture struct {
	Code       string `json:"code"`
	SourceLine int    `json:"source_line"`
	SinkLine   int    `json:"sink_line"`
}

// PoCCheck validates a recipe's PoC for its class: the closed verify
// template, its bounded parameters, and a template whose oracle proves the
// class. It returns an error that quotes no value.
type PoCCheck func(class string, poc json.RawMessage) error

// classes maps the class names a recipe may use to the reader's classes.
var classes = map[string]reader.Class{
	"sql_injection":      reader.ClassSQLInjection,
	"command_injection":  reader.ClassCommandInjection,
	"path_traversal":     reader.ClassPathTraversal,
	"ssrf":               reader.ClassSSRF,
	"template_injection": reader.ClassTemplateInjection,
	"nosql_injection":    reader.ClassNoSQLInjection,
}

// Classes returns the class names a recipe may use, in the reader's order.
func Classes() []string {
	out := make([]string, 0, len(classes))
	for c := reader.ClassSQLInjection; c <= reader.ClassNoSQLInjection; c++ {
		out = append(out, c.String())
	}
	return out
}

// Parse reads and checks a recipe without any model call: what
// `creep recipe lint` runs. A parsed recipe has not proved its fixtures;
// only Load returns a recipe that may be used. check validates the PoC; a
// recipe with a PoC and no check is refused.
func Parse(data []byte, check PoCCheck) (*Recipe, error) {
	if len(data) > MaxFileBytes {
		return nil, fmt.Errorf("%w: larger than %d bytes", ErrInvalid, MaxFileBytes)
	}
	if !utf8.Valid(data) {
		return nil, fmt.Errorf("%w: not UTF-8", ErrInvalid)
	}
	var r Recipe
	if err := decodeStrict(data, &r); err != nil {
		return nil, err
	}
	if err := r.validate(check); err != nil {
		return nil, err
	}
	return &r, nil
}

// decodeStrict decodes one JSON object into r: unknown fields, trailing
// data, and keys repeated or spelled in another case are refused, since
// encoding/json would match "Hint" to hint and keep the last of two.
func decodeStrict(data []byte, r *Recipe) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(r); err != nil {
		return fmt.Errorf("%w: not the recipe JSON format", ErrInvalid)
	}
	if len(bytes.TrimSpace(data[dec.InputOffset():])) > 0 {
		return fmt.Errorf("%w: trailing data after the recipe", ErrInvalid)
	}
	return checkKeys(data)
}

// checkKeys refuses a key that is not lower-case snake case, as every
// recipe and verify.Request key is, or that repeats in one object. data is
// one valid JSON value (decodeStrict decoded it), so a token error cannot
// happen; the walk is linear in data.
func checkKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	var stack []map[string]bool // keys seen per open object; nil for an array
	wantKey := false
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("%w: not the recipe JSON format", ErrInvalid)
		}
		top := len(stack) - 1
		if wantKey && tok != json.Delim('}') {
			name, _ := tok.(string)
			if !snakeKey(name) || stack[top][name] {
				return fmt.Errorf("%w: a key is not lower-case snake case, or repeats in one object", ErrInvalid)
			}
			stack[top][name] = true
			wantKey = false
			continue
		}
		switch tok {
		case json.Delim('{'):
			stack = append(stack, map[string]bool{})
		case json.Delim('['):
			stack = append(stack, nil)
		case json.Delim('}'), json.Delim(']'):
			stack = stack[:top]
		}
		// After a value or an object's open, an object expects its next key.
		wantKey = len(stack) > 0 && stack[len(stack)-1] != nil
	}
}

// snakeKey reports a key of 1 to MaxKeyBytes bytes: a lower-case letter,
// then lower-case letters and underscores.
func snakeKey(k string) bool {
	if k == "" || len(k) > MaxKeyBytes || k[0] < 'a' || k[0] > 'z' {
		return false
	}
	for i := 1; i < len(k); i++ {
		if c := k[i]; (c < 'a' || c > 'z') && c != '_' {
			return false
		}
	}
	return true
}
