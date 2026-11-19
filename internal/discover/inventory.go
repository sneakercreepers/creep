package discover

import (
	"bytes"
	_ "embed" // the inventory table is data in inventory.txt
	"fmt"
	"path"
	"strings"
	"sync"
)

// Language is a source language the inventory knows: an ID for reports
// and a hint in the prompt, never a choice of analysis path. The zero
// value means the file is not source.
type Language uint8

// languageNames are the language IDs; Language(i+1) is languageNames[i].
var languageNames = []string{
	"python", "javascript", "typescript", "go", "php", "java", "kotlin",
	"scala", "groovy", "clojure", "ruby", "csharp", "vb", "fsharp", "rust",
	"elixir", "erlang", "swift", "dart", "perl", "lua", "c", "cpp", "vue",
	"svelte", "coldfusion",
}

// canaryLanguage labels the canary section, which is JavaScript.
var canaryLanguage = Language(indexOf(languageNames, "javascript") + 1) //nolint:gosec // G115: a short list

// Manifest is a package manifest kind; Manifest(i+1) is manifestNames[i].
// The zero value is none.
type Manifest uint8

var manifestNames = []string{
	"npm", "gomod", "maven", "gradle", "pip", "pyproject", "pipenv",
	"bundler", "composer", "cargo", "nuget", "mix",
}

// Container is a container build or compose file kind;
// Container(i+1) is containerNames[i]. The zero value is none.
type Container uint8

var containerNames = []string{"dockerfile", "compose"}

// String returns the language ID, or "unknown".
func (l Language) String() string { return nameOf(languageNames, int(l)) }

// String returns the manifest ID, or "unknown".
func (m Manifest) String() string { return nameOf(manifestNames, int(m)) }

// String returns the container file ID, or "unknown".
func (c Container) String() string { return nameOf(containerNames, int(c)) }

func nameOf(names []string, v int) string {
	if v < 1 || v > len(names) {
		return "unknown"
	}
	return names[v-1]
}

// Entry is what the inventory says a file is. At most one field is set.
type Entry struct {
	Language  Language
	Manifest  Manifest
	Container Container
}

// match kinds, in precedence order.
const (
	matchName = iota
	matchGlob
	matchExt
	matchShebang
	matchKinds
)

var matchNames = []string{"name", "glob", "ext", "shebang"}

// binaryProbeBytes is how much of a source file is searched for a NUL.
const binaryProbeBytes = 8 << 10

// inventoryTable holds one exact lookup per match kind; globs are a list
// tried in table order.
type inventoryTable struct {
	exact [matchKinds]map[string]Entry
	globs []globRule
}

type globRule struct {
	prefix, suffix string
	entry          Entry
}

//go:embed inventory.txt
var inventoryData string

// loadInventory parses the embedded table once. A broken table is an
// error every Run returns; inventory_test.go keeps the shipped one valid.
var loadInventory = sync.OnceValues(func() (inventoryTable, error) {
	return parseInventory(inventoryData)
})

func parseInventory(data string) (inventoryTable, error) {
	var t inventoryTable
	for i := range t.exact {
		t.exact[i] = map[string]Entry{}
	}
	for n, fields := range tableRows(data) {
		if err := t.add(fields); err != nil {
			return inventoryTable{}, fmt.Errorf("inventory.txt line %d: %w", n, err)
		}
	}
	return t, nil
}

func (t *inventoryTable) add(fields []string) error {
	if len(fields) != 4 {
		return fmt.Errorf("want <match> <pattern> <class> <id>, got %d fields", len(fields))
	}
	kind := indexOf(matchNames, fields[0])
	if kind < 0 {
		return fmt.Errorf("unknown match %q", fields[0])
	}
	entry, err := entryFor(fields[2], fields[3])
	if err != nil {
		return err
	}
	key := fields[1]
	if _, dup := t.exact[kind][key]; dup {
		return fmt.Errorf("%s %q appears twice", fields[0], key)
	}
	t.exact[kind][key] = entry
	if kind != matchGlob {
		return nil
	}
	prefix, suffix, ok := strings.Cut(key, "*")
	if !ok || strings.Contains(suffix, "*") {
		return fmt.Errorf("glob %q needs exactly one *", key)
	}
	t.globs = append(t.globs, globRule{prefix, suffix, entry})
	return nil
}

func entryFor(class, id string) (Entry, error) {
	names := map[string][]string{"language": languageNames, "manifest": manifestNames, "container": containerNames}[class]
	i := indexOf(names, id)
	if i < 0 {
		return Entry{}, fmt.Errorf("unknown %s %q", class, id)
	}
	v := uint8(i + 1) //nolint:gosec // G115: the name lists hold fewer than 256 entries
	switch class {
	case "language":
		return Entry{Language: Language(v)}, nil
	case "manifest":
		return Entry{Manifest: Manifest(v)}, nil
	}
	return Entry{Container: Container(v)}, nil
}

func indexOf(list []string, s string) int {
	for i, v := range list {
		if v == s {
			return i
		}
	}
	return -1
}

// classify says what the file at name is. content may be nil when the
// file could not be read; then only its name decides.
func (t inventoryTable) classify(name string, content []byte) Entry {
	base := baseName(name)
	e, found := t.byName(base)
	if !found && path.Ext(base) == "" {
		e = t.exact[matchShebang][interpreter(content)]
	}
	if e.Language != 0 && bytes.IndexByte(content[:min(len(content), binaryProbeBytes)], 0) >= 0 {
		return Entry{}
	}
	return e
}

func (t inventoryTable) byName(base string) (Entry, bool) {
	if e, ok := t.exact[matchName][base]; ok {
		return e, true
	}
	for _, g := range t.globs {
		if len(base) >= len(g.prefix)+len(g.suffix) && strings.HasPrefix(base, g.prefix) && strings.HasSuffix(base, g.suffix) {
			return g.entry, true
		}
	}
	e, ok := t.exact[matchExt][strings.ToLower(path.Ext(base))]
	return e, ok
}

func baseName(name string) string {
	return name[strings.LastIndexAny(name, `/\`)+1:]
}

// maxShebangBytes bounds the first line read for an interpreter.
const maxShebangBytes = 256

// interpreter returns the program a "#!" line runs, through env, with its
// version digits dropped ("python3.12" is "python"), or "".
func interpreter(content []byte) string {
	if !bytes.HasPrefix(content, []byte("#!")) {
		return ""
	}
	line := content[2:min(len(content), maxShebangBytes)]
	if i := bytes.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	fields := strings.Fields(string(line))
	if len(fields) > 0 && path.Base(fields[0]) == "env" {
		fields = dropFlags(fields[1:])
	}
	if len(fields) == 0 {
		return ""
	}
	return strings.TrimRight(path.Base(fields[0]), "0123456789.")
}

// dropFlags skips env's options, such as -S, before the program name.
func dropFlags(fields []string) []string {
	for len(fields) > 0 && strings.HasPrefix(fields[0], "-") {
		fields = fields[1:]
	}
	return fields
}
