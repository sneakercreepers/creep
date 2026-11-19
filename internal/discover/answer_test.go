package discover

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestValidate(t *testing.T) {
	ok := func() Answer {
		return Answer{
			Entries: []EntryProposal{entryAt(0, 2, 3, "http"), entryAt(maxFiles-1, 1, 1, "cli")},
			Sinks:   []SinkProposal{sinkAt(0, 3, "sql", 0), sinkAt(2, 9, "nosql", -1)},
			Auth:    []AuthProposal{authAt(0, 2, 2)},
		}
	}
	tests := []struct {
		name string
		edit func(a *Answer)
		ok   bool
	}{
		{"valid", func(*Answer) {}, true},
		{"empty arrays", func(a *Answer) {
			*a = Answer{Entries: []EntryProposal{}, Sinks: []SinkProposal{}, Auth: []AuthProposal{}}
		}, true},
		{"nil entries", func(a *Answer) { a.Entries = nil }, false},
		{"nil sinks", func(a *Answer) { a.Sinks = nil }, false},
		{"nil auth", func(a *Answer) { a.Auth = nil }, false},
		{"entry file -1", func(a *Answer) { a.Entries[0].File = num(-1) }, false},
		{"entry file past the batch cap", func(a *Answer) { a.Entries[1].File = num(maxFiles) }, false},
		{"sink file past the batch cap", func(a *Answer) { a.Sinks[1].File = num(maxFiles) }, false},
		{"auth file -1", func(a *Answer) { a.Auth[0].File = num(-1) }, false},
		{"entry end before start", func(a *Answer) { a.Entries[0].End = num(1) }, false},
		{"entry past MaxLine", func(a *Answer) { a.Entries[0].End = num(MaxLine + 1) }, false},
		{"entry kind case", func(a *Answer) { a.Entries[0].Kind = "HTTP" }, false},
		{"sink line 0", func(a *Answer) { a.Sinks[0].Line = num(0) }, false},
		{"sink kind eval", func(a *Answer) { a.Sinks[0].Kind = "eval" }, false},
		{"sink entry past entries", func(a *Answer) { a.Sinks[0].Entry = num(2) }, false},
		{"sink entry in another file", func(a *Answer) { a.Sinks[0].Entry = num(1) }, false},
		{"sink entry -2", func(a *Answer) { a.Sinks[0].Entry = num(-2) }, false},
		{"auth end before start", func(a *Answer) { a.Auth[0].Start = num(3) }, false},
		{"entries at the cap", func(a *Answer) { a.Entries = repeatEntries(0, MaxEntriesPerFile) }, true},
		{"entries over the cap", func(a *Answer) { a.Entries = repeatEntries(0, MaxEntriesPerFile+1) }, false},
		{"cap counted per file", func(a *Answer) {
			a.Entries = append(repeatEntries(1, MaxEntriesPerFile), repeatEntries(2, MaxEntriesPerFile)...)
			a.Sinks[0].Entry = num(-1)
		}, true},
	}
	for _, tt := range tests {
		a := ok()
		tt.edit(&a)
		err := a.Validate()
		if (err == nil) != tt.ok {
			t.Errorf("%s: Validate = %v, want ok %v", tt.name, err, tt.ok)
		}
		if err != nil && strings.ContainsAny(err.Error(), "\"'") {
			t.Errorf("%s: message %q quotes a value", tt.name, err)
		}
	}
}

func repeatEntries(file, n int) []EntryProposal {
	out := make([]EntryProposal, n)
	for i := range out {
		out[i] = entryAt(file, 1, 1, "rpc")
	}
	return out
}

// TestSchemaIsClosed walks every object in the schema: each must set
// additionalProperties false and require every property, so strict mode
// accepts no free-text key.
func TestSchemaIsClosed(t *testing.T) {
	var root map[string]any
	if err := json.Unmarshal(Schema(), &root); err != nil {
		t.Fatalf("schema is not JSON: %v", err)
	}
	objects := 0
	var walk func(node map[string]any)
	walk = func(node map[string]any) {
		if node["type"] == "object" {
			objects++
			props, _ := node["properties"].(map[string]any)
			required, _ := node["required"].([]any)
			if node["additionalProperties"] != false || len(required) != len(props) {
				t.Errorf("object %v is not closed", node)
			}
			for _, p := range props {
				walk(p.(map[string]any))
			}
		}
		if node["type"] == "string" && node["enum"] == nil {
			t.Errorf("string without an enum: %v", node)
		}
		if items, ok := node["items"].(map[string]any); ok {
			walk(items)
		}
	}
	walk(root)
	if objects != 4 {
		t.Errorf("schema has %d objects, want 4 (root, entry, sink, auth)", objects)
	}
}

// The grammar names every enum value and key the schema allows, and its
// one-digit file rule covers exactly the indexes 0..maxFiles-1.
func TestGrammarMatchesSchema(t *testing.T) {
	g := Grammar()
	for _, v := range append(append(sinkKindNames(), entryKindNames...), "file", "entries", "sinks", "auth", "entry", "line", "start", "end", "kind") {
		if !strings.Contains(g, `\"`+v+`\"`) {
			t.Errorf("grammar does not name %q", v)
		}
	}
	if maxFiles != 9 || !strings.Contains(g, "fileno ::= [0-8]") {
		t.Errorf("maxFiles %d does not match the grammar's file rule", maxFiles)
	}
}
