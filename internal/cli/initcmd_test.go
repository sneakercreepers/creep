package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/sneakercreepers/creep/internal/config"
	"github.com/sneakercreepers/creep/internal/exitcode"
)

// TestInitWritesTemplate checks the file, the hint on stdout, that nothing
// else is written, and that `config explain` shows the same values and
// sources before and after, with and without a user file.
func TestInitWritesTemplate(t *testing.T) {
	tests := []struct {
		name string
		user string
	}{
		{"defaults", ""},
		{"user file", "gates:\n  pr: probable:high\nbudget:\n  max_calls: 10\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isolateUserConfig(t)
			writeUserConfig(t, tt.user)
			dir := t.TempDir()
			t.Chdir(dir)
			before := explainJSON(t)
			code, stdout, stderr := run("init")
			if code != exitcode.OK {
				t.Fatalf("init exit %d: %s", code, stderr)
			}
			assertContains(t, "stdout", stdout, []string{"~/.creep/config.yaml", "--config", "policy", "model:\n  preset: claude-code"})
			assertOnlyProjectFile(t, dir)
			if after := explainJSON(t); after != before {
				t.Errorf("creep.yaml changed effective values:\nbefore %s\nafter  %s", before, after)
			}
		})
	}
}

func explainJSON(t *testing.T) string {
	t.Helper()
	code, stdout, stderr := run("config", "explain", "--format", "json")
	if code != exitcode.OK {
		t.Fatalf("config explain exit %d: %s", code, stderr)
	}
	return stdout
}

func assertOnlyProjectFile(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != projectFile {
		t.Errorf("init wrote %v, want only %s", entries, projectFile)
	}
	got, err := os.ReadFile(filepath.Join(dir, projectFile))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, config.ProjectTemplate()) {
		t.Errorf("creep.yaml is not the template:\n%s", got)
	}
}

// TestInitRefusesExisting plants each kind of entry at creep.yaml: init
// exits 2, leaves it as it was and never writes through a link.
func TestInitRefusesExisting(t *testing.T) {
	tests := []struct {
		name  string
		plant func(t *testing.T, outside string)
		want  string
	}{
		{"regular file", func(t *testing.T, _ string) { writeFile(t, projectFile, "gates:\n  pr: probable:high\n") }, "already exists"},
		{"directory", func(t *testing.T, _ string) { mustMkdir(t, projectFile) }, "link, directory or special file"},
		{"link to a file outside", func(t *testing.T, outside string) {
			writeFile(t, outside, "kept\n")
			symlinkOrSkip(t, outside, projectFile)
		}, "link, directory or special file"},
		{"dangling link", func(t *testing.T, outside string) { symlinkOrSkip(t, outside, projectFile) }, "link, directory or special file"},
		{"directory link", func(t *testing.T, outside string) {
			mustMkdir(t, outside)
			linkDir(t, outside, projectFile)
		}, "link, directory or special file"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			outside := filepath.Join(t.TempDir(), "target")
			t.Chdir(t.TempDir())
			tt.plant(t, outside)
			before := snapshot(t, outside)
			code, stdout, stderr := run("init")
			if code != exitcode.ConfigError || stdout != "" {
				t.Fatalf("init exit %d, stdout %q, want exit 2 and no output", code, stdout)
			}
			assertContains(t, "stderr", stderr, []string{"creep init: ", tt.want, "left unchanged"})
			if after := snapshot(t, outside); after != before {
				t.Errorf("link target changed: %q -> %q", before, after)
			}
		})
	}
}

// TestInitCreateIsExclusive plants the file after the check, as a racing
// process would: the O_EXCL create refuses it and keeps its content.
func TestInitCreateIsExclusive(t *testing.T) {
	t.Chdir(t.TempDir())
	root, err := os.OpenRoot(".")
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := refuseExisting(root); err != nil {
		t.Fatalf("empty directory refused: %v", err)
	}
	writeFile(t, projectFile, "raced\n")
	if err := createProjectFile(root); !errors.Is(err, errProjectExists) {
		t.Fatalf("create over a planted file: %v, want errProjectExists", err)
	}
	if got := snapshot(t, projectFile); got != "raced\n" {
		t.Errorf("planted file changed to %q", got)
	}
}

// snapshot is the content of path, or a marker when it is absent or not a
// regular file.
func snapshot(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		return "unreadable"
	}
	return string(data)
}

// TestInitRefusesNonTextFormat checks that init, which prints only text,
// refuses a machine format instead of ignoring it, and writes nothing.
func TestInitRefusesNonTextFormat(t *testing.T) {
	for _, format := range []string{"json", "sarif", "markdown"} {
		t.Run(format, func(t *testing.T) {
			t.Chdir(t.TempDir())
			isolateUserConfig(t)
			code, _, stderr := run("--format", format, "init")
			if code != exitcode.ConfigError || !bytes.Contains([]byte(stderr), []byte("prints text only")) {
				t.Fatalf("exit %d, stderr %q", code, stderr)
			}
			if _, err := os.Lstat(projectFile); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("creep.yaml written: %v", err)
			}
		})
	}
	t.Run("explicit text", func(t *testing.T) {
		t.Chdir(t.TempDir())
		isolateUserConfig(t)
		if code, _, stderr := run("--format", "text", "init"); code != exitcode.OK {
			t.Fatalf("exit %d, stderr %q", code, stderr)
		}
	})
}
