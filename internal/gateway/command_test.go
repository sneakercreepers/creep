package gateway

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestSplitCommandLine(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{`claude -p --tools "" --strict-mcp-config --output-format json`, []string{"claude", "-p", "--tools", "", "--strict-mcp-config", "--output-format", "json"}},
		{"  ollama\trun  llama3 ", []string{"ollama", "run", "llama3"}},
		{`'C:\Program Files\llm.exe' -m 'gpt 4'`, []string{`C:\Program Files\llm.exe`, "-m", "gpt 4"}},
		{`codex exec "a;b|c"`, []string{"codex", "exec", "a;b|c"}},
		{`x a"b c"d`, []string{"x", "ab cd"}},
	}
	for _, tt := range tests {
		got, err := splitCommandLine(tt.in)
		if err != nil || !slices.Equal(got, tt.want) {
			t.Errorf("split(%q) = %q, %v; want %q", tt.in, got, err, tt.want)
		}
	}
}

// Security (#6): nothing a shell would interpret is accepted unquoted, so a
// configured command can never pipe, substitute or redirect.
func TestSplitCommandLineRefuses(t *testing.T) {
	bad := []string{
		"", "   ", `""`, "claude -p | sh", "claude; rm -rf /", "claude $(id)", "claude `id`",
		"claude > out", "claude && x", "claude ~/x", "claude *", "claude 'open",
		"claude -p\nrm", "claude \x00", "claude $HOME", "x #c", "x {a,b}",
		strings.Repeat("a ", maxCommandArgs+1), strings.Repeat("a", maxCommandBytes+1),
	}
	for _, s := range bad {
		if got, err := splitCommandLine(s); !errors.Is(err, ErrCommand) {
			t.Errorf("split(%q) = %q, %v; want ErrCommand", s, got, err)
		}
	}
}

func TestNewCommandRefuses(t *testing.T) {
	repo := t.TempDir()
	inRepo := filepath.Join(repo, "claude.exe")
	if err := os.WriteFile(inRepo, []byte("x"), 0o700); err != nil { //nolint:gosec // G306: LookPath needs an executable file
		t.Fatal(err)
	}
	tests := []struct {
		name string
		edit func(*CommandOptions)
	}{
		{"relative path", func(o *CommandOptions) { o.Run = "./claude -p" }},
		{"relative dir", func(o *CommandOptions) { o.Run = `bin\claude -p` }},
		{"not found", func(o *CommandOptions) { o.Run = "creep-no-such-program-6" }},
		{"inside repo", func(o *CommandOptions) { o.Run = "'" + inRepo + "'"; o.RepoDir = repo }},
		{"timeout zero", func(o *CommandOptions) { o.Timeout = 0 }},
		{"timeout long", func(o *CommandOptions) { o.Timeout = 2 * time.Hour }},
		{"output tiny", func(o *CommandOptions) { o.MaxOutputBytes = 10 }},
		{"output huge", func(o *CommandOptions) { o.MaxOutputBytes = maxResponseBytes + 1 }},
		{"env name", func(o *CommandOptions) { o.Env = []string{"A=B"} }},
		{"env empty", func(o *CommandOptions) { o.Env = []string{""} }},
		{"no getenv", func(o *CommandOptions) { o.Getenv = nil }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := fakeOptions(t, "echo", 10*time.Second)
			tt.edit(&opts)
			if _, err := NewCommand(opts); !errors.Is(err, ErrCommand) {
				t.Errorf("NewCommand = %v, want ErrCommand", err)
			}
		})
	}
}

// A program in the current directory is never found by name, even where
// the platform would search it (Windows), because that is the repository.
func TestNewCommandIgnoresCurrentDirectory(t *testing.T) {
	dir := t.TempDir()
	name := "creep-planted-cli"
	file := name
	if runtime.GOOS == "windows" {
		file += ".exe"
	}
	if err := os.WriteFile(filepath.Join(dir, file), []byte("x"), 0o700); err != nil { //nolint:gosec // G306: LookPath needs an executable file
		t.Fatal(err)
	}
	t.Chdir(dir)
	t.Setenv("PATH", "."+string(os.PathListSeparator)+os.Getenv("PATH"))
	opts := fakeOptions(t, "echo", time.Second)
	opts.Run = name
	if _, err := NewCommand(opts); !errors.Is(err, ErrCommand) {
		t.Fatalf("NewCommand = %v, want ErrCommand", err)
	}
}

// The endpoint changes with the arguments and env names, never with env
// values, and is a valid policy and consent-store entry.
func TestCommandEndpoint(t *testing.T) {
	a := fakeCommand(t, "echo", time.Second)
	opts := fakeOptions(t, "other-mode", time.Second)
	b, err := NewCommand(opts)
	if err != nil {
		t.Fatal(err)
	}
	opts.Run += " --verbose"
	c, err := NewCommand(opts)
	if err != nil {
		t.Fatal(err)
	}
	if a.Endpoint() != b.Endpoint() || a.Endpoint() == c.Endpoint() {
		t.Errorf("endpoints %s %s %s", a.Endpoint(), b.Endpoint(), c.Endpoint())
	}
	if got, err := parseOrigin(a.Endpoint()); err != nil || got != a.Endpoint() {
		t.Errorf("parseOrigin(%s) = %q, %v", a.Endpoint(), got, err)
	}
	for _, bad := range []string{"command://", "command://x", "command://X-0123456789abcdef", "command://x-0123456789abcdef/p"} {
		if _, err := parseOrigin(bad); err == nil {
			t.Errorf("parseOrigin(%q) accepted", bad)
		}
	}
}

func TestSlug(t *testing.T) {
	for in, want := range map[string]string{"claude": "claude", "ollama": "ollama", "my_cli.v2": "my-cli-v2", "---": "cmd", "日本": "cmd"} {
		if got := slug(in); got != want || !isCommandKey(commandScheme+got+"-0123456789abcdef") {
			t.Errorf("slug(%q) = %q, want %q", in, got, want)
		}
	}
}

// A Command can only run through EgressLog.Exec: its exported methods
// describe it and none starts it, so no caller can skip consent, the budget
// or egress.log (ADR 0014).
func TestCommandIsOpaque(t *testing.T) {
	var names []string
	typ := reflect.TypeFor[*Command]()
	for i := range typ.NumMethod() {
		names = append(names, typ.Method(i).Name)
	}
	if !slices.Equal(names, []string{"Args", "Endpoint", "Program"}) {
		t.Errorf("*Command methods = %v; a new one must not run the program", names)
	}
	for _, f := range reflect.VisibleFields(reflect.TypeFor[Command]()) {
		if f.IsExported() {
			t.Errorf("Command field %s is exported", f.Name)
		}
	}
}
