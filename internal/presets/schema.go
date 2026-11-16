package presets

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"slices"
	"strings"
	"unicode"

	"go.yaml.in/yaml/v3"
)

// SchemaVersion is the only preset file version this build reads.
const SchemaVersion = 1

// ModelPlaceholder is the whole argument replaced by model.name.
const ModelPlaceholder = "{model}"

// Limits keep a preset reviewable and under the gateway's command-line caps.
const (
	maxFileBytes   = 16 << 10
	maxArgs        = 32
	maxArgBytes    = 256
	maxDescription = 200
)

// Preset is one model CLI. The YAML keys are the schema; any other key is
// an error.
type Preset struct {
	Version     int    `yaml:"version"`
	Name        string `yaml:"name"`        // equals the file name without .yaml
	Description string `yaml:"description"` // one line for humans
	Docs        string `yaml:"docs"`        // https URL of the CLI's flag reference
	Program     string `yaml:"program"`     // bare program name, found on PATH by the gateway
	// Args follow the program. {model} as a whole argument is replaced by
	// model.name, which is then required.
	Args []string `yaml:"args"`
	// ToolsOff lists the argument runs (e.g. [--tools, ""]) that switch the
	// CLI's tools off; each must appear in Args in that order. Empty only
	// when NoTools is true.
	ToolsOff [][]string `yaml:"tools_off"`
	// NoTools says the CLI has no tools to switch off (ollama run).
	NoTools bool `yaml:"no_tools"`
}

var (
	namePattern    = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	programPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
)

// parse strictly decodes one preset file and validates it. file is the
// file name the preset was read from; the preset's name must match it.
func parse(file string, data []byte) (Preset, error) {
	if len(data) > maxFileBytes {
		return Preset{}, fmt.Errorf("preset %q: over %d bytes", file, maxFileBytes)
	}
	var p Preset
	if err := decodeOne(data, &p); err != nil {
		return Preset{}, fmt.Errorf("preset %q: %w", file, err)
	}
	if err := p.validate(); err != nil {
		return Preset{}, fmt.Errorf("preset %q: %w", file, err)
	}
	if want := strings.TrimSuffix(path.Base(file), ".yaml"); p.Name != want {
		return Preset{}, fmt.Errorf("preset %q: name %q must equal the file name %q", file, p.Name, want)
	}
	return p, nil
}

// decodeOne decodes exactly one YAML document with unknown keys refused.
// yaml/v3 also refuses duplicate keys.
func decodeOne(data []byte, out *Preset) error {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	if err := dec.Decode(new(yaml.Node)); !errors.Is(err, io.EOF) {
		return errors.New("decode: only one YAML document is allowed")
	}
	return nil
}

func (p Preset) validate() error {
	switch {
	case p.Version != SchemaVersion:
		return fmt.Errorf("version %d: want %d", p.Version, SchemaVersion)
	case !namePattern.MatchString(p.Name) || len(p.Name) > 64:
		return fmt.Errorf("name %q: want lowercase letters, digits and single dashes", p.Name)
	case p.Description == "" || len(p.Description) > maxDescription || !isPlainText(p.Description):
		return fmt.Errorf("description: want one line of at most %d characters", maxDescription)
	case !strings.HasPrefix(p.Docs, "https://") || !isPlainText(p.Docs) || strings.Contains(p.Docs, " "):
		return fmt.Errorf("docs %q: want an https URL", p.Docs)
	case !programPattern.MatchString(p.Program):
		return fmt.Errorf("program %q: want a bare program name, not a path or a command line", p.Program)
	}
	if err := checkArgs(p.Args); err != nil {
		return err
	}
	return p.checkToolsOff()
}

// checkArgs refuses arguments CommandLine could not quote losslessly and a
// partial or repeated {model}.
func checkArgs(args []string) error {
	if len(args) > maxArgs {
		return fmt.Errorf("args: more than %d", maxArgs)
	}
	for _, a := range args {
		switch {
		case len(a) > maxArgBytes || !isPlainText(a):
			return fmt.Errorf("args: %q has control characters or is over %d bytes", a, maxArgBytes)
		case strings.Contains(a, "'") && strings.Contains(a, `"`):
			return fmt.Errorf("args: %q has both quote kinds", a)
		case a != ModelPlaceholder && strings.Contains(a, "{model"):
			return fmt.Errorf("args: %q: %s must be a whole argument", a, ModelPlaceholder)
		}
	}
	if n := countOf(args, ModelPlaceholder); n > 1 {
		return fmt.Errorf("args: %s appears %d times", ModelPlaceholder, n)
	}
	return nil
}

// checkToolsOff requires the tool-disabling flags to be listed and present,
// so the canary's fix message and reviewers can name each one.
func (p Preset) checkToolsOff() error {
	if p.NoTools != (len(p.ToolsOff) == 0) {
		return errors.New("tools_off: list the flags that switch tools off, or set no_tools: true with tools_off: [] for a CLI without tools")
	}
	for _, run := range p.ToolsOff {
		if len(run) == 0 {
			return errors.New("tools_off: empty entry")
		}
		if !containsRun(p.Args, run) {
			return fmt.Errorf("tools_off: %q is not in args", run)
		}
	}
	return nil
}

// containsRun reports whether run appears in args as consecutive items.
func containsRun(args, run []string) bool {
	for i := 0; i+len(run) <= len(args); i++ {
		if slices.Equal(args[i:i+len(run)], run) {
			return true
		}
	}
	return false
}

func countOf(args []string, s string) int {
	n := 0
	for _, a := range args {
		if a == s {
			n++
		}
	}
	return n
}

// isPlainText refuses control characters and whitespace other than spaces,
// which could hide an argument in a terminal or a review diff.
func isPlainText(s string) bool {
	return strings.IndexFunc(s, func(r rune) bool {
		return r != ' ' && (unicode.IsSpace(r) || !unicode.IsPrint(r))
	}) < 0
}
