package cli

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/sneakercreepers/creep/internal/exitcode"
)

// The CLI contract (#135, architecture §4): `creep --help` and every flag's
// name, type, default and commands are pinned, so removing, renaming or
// retyping a flag shows up as a golden diff that only -update accepts.
var (
	helpGolden  = filepath.Join("testdata", "help.golden")
	flagsGolden = filepath.Join("testdata", "flags.golden")
)

// flagSamples are the arguments that make a flag valid on its own. A flag
// not listed takes its default, or "x" when the default is empty.
var flagSamples = map[string][]string{
	"baseline-write": {"--baseline-write", "--baseline", "x"},
	"price-in":       {"--price-in", "1"},
	"price-out":      {"--price-out", "1"},
}

type flagRow struct {
	name, kind, def string
	commands        []string
}

func TestHelpGolden(t *testing.T) {
	code, help, stderr := run("--help")
	if code != exitcode.OK {
		t.Fatalf("creep --help exit %d: %s", code, stderr)
	}
	tests := []struct {
		name  string
		got   string
		match bool
	}{
		{"creep --help", help, true},
		{"broken: flag line removed", dropLine(help, "--stats"), false},
		{"broken: exit code reworded", strings.Replace(help, "gate exceeded", "findings found", 1), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checkGolden(t, helpGolden, tt.got, tt.match)
		})
	}
}

func TestFlagsGolden(t *testing.T) {
	rows := currentFlagRows(t)
	tests := []struct {
		name  string
		rows  func() []flagRow
		match bool
	}{
		{"every flag", func() []flagRow { return rows }, true},
		{"broken: flag removed", func() []flagRow { return rows[1:] }, false},
		{"broken: flag renamed", func() []flagRow { return editRow(rows, func(r *flagRow) { r.name += "s" }) }, false},
		{"broken: type changed", func() []flagRow { return editRow(rows, func(r *flagRow) { r.kind = "int" }) }, false},
		{"broken: default changed", func() []flagRow { return editRow(rows, func(r *flagRow) { r.def = `"y"` }) }, false},
		{"broken: command dropped", func() []flagRow { return editRow(rows, func(r *flagRow) { r.commands = r.commands[1:] }) }, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checkGolden(t, flagsGolden, renderFlags(tt.rows()), tt.match)
		})
	}
}

// checkGolden compares got with the golden at path; a broken case must
// differ, and only the matching case may rewrite the file under -update.
func checkGolden(t *testing.T, path, got string, match bool) {
	t.Helper()
	if match && *updateGolden {
		mustWrite(t, path, got)
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	diff := lineDiff(strings.ReplaceAll(string(want), "\r\n", "\n"), got)
	if match && diff != "" {
		t.Errorf("output differs from %s (rerun with -update to accept):\n%s", path, diff)
	}
	if !match && diff == "" {
		t.Errorf("the golden comparison missed a change to %s", path)
	}
}

// currentFlagRows lists every flag with the implemented commands that accept
// it, found through the real parse and per-command checks: "creep <cmd>
// <flag> --help" exits 0 only when cmd takes the flag.
func currentFlagRows(t *testing.T) []flagRow {
	t.Helper()
	cfg := filepath.Join(t.TempDir(), "creep.yaml")
	mustWrite(t, cfg, "{}\n")
	samples := map[string][]string{"config": {"--config", cfg}}
	opts := defaultOptions()
	var rows []flagRow
	newFlagSet("creep", &opts).VisitAll(func(f *flag.Flag) {
		args := flagArgs(f, samples)
		row := flagRow{name: "--" + f.Name, kind: fmt.Sprintf("%T", f.Value.(flag.Getter).Get()), def: fmt.Sprintf("%q", f.DefValue)}
		for _, c := range implementedCommands() {
			if code, _, _ := run(append([]string{c, "--help"}, args...)...); code == exitcode.OK {
				row.commands = append(row.commands, c)
			}
		}
		if len(row.commands) == 0 {
			t.Errorf("no command accepts %v: add a valid sample to flagSamples", args)
		}
		rows = append(rows, row)
	})
	return rows
}

func flagArgs(f *flag.Flag, local map[string][]string) []string {
	if args, ok := local[f.Name]; ok {
		return args
	}
	if args, ok := flagSamples[f.Name]; ok {
		return args
	}
	if b, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && b.IsBoolFlag() {
		return []string{"--" + f.Name}
	}
	value := f.DefValue
	if value == "" {
		value = "x"
	}
	return []string{"--" + f.Name, value}
}

// implementedCommands leaves out the stubs, whose summary says so.
func implementedCommands() []string {
	var names []string
	for _, c := range commands {
		if !strings.HasSuffix(c.summary, "(not implemented yet)") {
			names = append(names, c.name)
		}
	}
	return names
}

func renderFlags(rows []flagRow) string {
	var b strings.Builder
	b.WriteString("# flag, type, default, commands that accept it (implemented commands only)\n")
	for _, r := range rows {
		fmt.Fprintf(&b, "%-17s %-8s %-7s %s\n", r.name, r.kind, r.def, strings.Join(r.commands, " "))
	}
	return b.String()
}

func editRow(rows []flagRow, edit func(*flagRow)) []flagRow {
	edited := slices.Clone(rows)
	edited[0].commands = slices.Clone(edited[0].commands)
	edit(&edited[0])
	return edited
}

func dropLine(s, substr string) string {
	lines := strings.Split(s, "\n")
	return strings.Join(slices.DeleteFunc(lines, func(l string) bool { return strings.Contains(l, substr) }), "\n")
}

// lineDiff returns a unified-style line diff of want and got, or "" when
// they are equal. Lines are matched by longest common subsequence; a copy
// lives in internal/exitcode.
func lineDiff(want, got string) string {
	if want == got {
		return ""
	}
	a, b := strings.Split(want, "\n"), strings.Split(got, "\n")
	lcs := make([][]int, len(a)+1)
	for i := range lcs {
		lcs[i] = make([]int, len(b)+1)
	}
	for i := len(a) - 1; i >= 0; i-- {
		for j := len(b) - 1; j >= 0; j-- {
			if a[i] == b[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else {
				lcs[i][j] = max(lcs[i+1][j], lcs[i][j+1])
			}
		}
	}
	var out strings.Builder
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		switch {
		case i < len(a) && j < len(b) && a[i] == b[j]:
			i, j = i+1, j+1
		case i < len(a) && (j == len(b) || lcs[i+1][j] >= lcs[i][j+1]):
			fmt.Fprintf(&out, "-%s\n", a[i])
			i++
		default:
			fmt.Fprintf(&out, "+%s\n", b[j])
			j++
		}
	}
	return out.String()
}
