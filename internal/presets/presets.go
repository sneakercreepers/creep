package presets

import (
	"embed"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync"
)

//go:embed *.yaml
var embedded embed.FS

// file is one preset file's name and bytes.
type file struct {
	name string
	data []byte
}

var (
	loadOnce sync.Once
	loaded   map[string]Preset
	loadErr  error
)

// all parses the embedded presets once. A broken embedded preset fails
// every lookup; TestEmbeddedPresets keeps that from shipping.
func all() (map[string]Preset, error) {
	loadOnce.Do(func() {
		files, err := embeddedFiles()
		if err != nil {
			loadErr = err
			return
		}
		loaded, loadErr = parseAll(files)
	})
	return loaded, loadErr
}

func embeddedFiles() ([]file, error) {
	entries, err := embedded.ReadDir(".")
	if err != nil {
		return nil, fmt.Errorf("read embedded presets: %w", err)
	}
	files := make([]file, 0, len(entries))
	for _, e := range entries {
		data, err := embedded.ReadFile(e.Name())
		if err != nil {
			return nil, fmt.Errorf("read embedded preset %q: %w", e.Name(), err)
		}
		files = append(files, file{name: e.Name(), data: data})
	}
	return files, nil
}

// parseAll parses every file and refuses two presets with the same name.
func parseAll(files []file) (map[string]Preset, error) {
	out := make(map[string]Preset, len(files))
	for _, f := range files {
		p, err := parse(f.name, f.data)
		if err != nil {
			return nil, err
		}
		if _, dup := out[p.Name]; dup {
			return nil, fmt.Errorf("preset %q: defined twice", p.Name)
		}
		out[p.Name] = p
	}
	return out, nil
}

// Names returns the embedded preset names, sorted.
func Names() []string {
	m, err := all()
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(m))
	for n := range m {
		names = append(names, n)
	}
	slices.Sort(names)
	return names
}

// Lookup returns the embedded preset called name.
func Lookup(name string) (Preset, error) {
	m, err := all()
	if err != nil {
		return Preset{}, err
	}
	p, ok := m[name]
	if !ok {
		return Preset{}, fmt.Errorf("unknown preset %q: want one of %s", name, strings.Join(Names(), ", "))
	}
	return p, nil
}

// NeedsModel reports whether the command line takes model.name.
func (p Preset) NeedsModel() bool {
	return slices.Contains(p.Args, ModelPlaceholder)
}

var modelNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,127}$`)

// CommandLine returns the preset as a model.run value: the program and its
// arguments, each quoted when the gateway's splitter would otherwise read
// it differently. model replaces {model}; it must look like a model name,
// so it can never become a flag or carry quotes.
func (p Preset) CommandLine(model string) (string, error) {
	parts := []string{p.Program}
	for _, a := range p.Args {
		if a == ModelPlaceholder {
			if !modelNamePattern.MatchString(model) {
				return "", fmt.Errorf("preset %q needs model.name, a model name such as llama3.1:8b, got %q", p.Name, model)
			}
			a = model
		}
		parts = append(parts, quoteArg(a))
	}
	return strings.Join(parts, " "), nil
}

// bareArg needs no quotes: nothing in it is a separator, a quote or shell
// syntax the gateway refuses outside quotes.
var bareArg = regexp.MustCompile(`^[A-Za-z0-9._/:=@+,%-]+$`)

// quoteArg quotes a for the gateway's splitter, where '...' and "..." keep
// text literally. checkArgs guarantees a never holds both quote kinds.
func quoteArg(a string) string {
	switch {
	case bareArg.MatchString(a):
		return a
	case strings.Contains(a, `"`):
		return "'" + a + "'"
	}
	return `"` + a + `"`
}
