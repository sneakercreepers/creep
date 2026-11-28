package discover

import (
	"strings"
	"testing"
)

// Acceptance (#366): a file in a language no inventory or tripwire row
// names is read whole, labeled text, and sent to discovery, and the run
// is complete. A file named like an image that holds text is read too, so
// a name cannot hide code.
func TestReadsAnyTextFile(t *testing.T) {
	files := map[string]string{
		"src/main.zig":   "const std = @import(\"std\");\npub fn main() void {\n    std.debug.print(\"zig-marker\", .{});\n}\n",
		"src/server.nim": "import std/osproc\nproc run(cmd: string) =\n  discard execCmd(cmd) # nim-marker\n",
		"assets/x.png":   "<?php system($_GET['c']); // png-marker\n",
	}
	var prompts []string
	res, err := discoverFiles(t, TierM, files, fakeClient(t, honestReply, &prompts))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Complete() {
		t.Fatalf("run is incomplete: %+v", res.Files)
	}
	for i, f := range res.Files {
		if f.Coverage != CoverageReadFull || f.Language != textLanguage || f.Batch == 0 {
			t.Errorf("file %d = %+v, want read in full as text and sent", i, f)
		}
	}
	all := strings.Join(prompts, "\n")
	for _, marker := range []string{"zig-marker", "nim-marker", "png-marker"} {
		if !strings.Contains(all, marker) {
			t.Errorf("no discovery call carries %s", marker)
		}
	}
	if !strings.Contains(all, "(text, ") {
		t.Error("no section is labeled text")
	}
}

func TestFormatOf(t *testing.T) {
	formats, err := loadFormats()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		want   string // "" for no format
		opened bool
	}{
		{"logo.PNG", "image", true},
		{"docs/guide.md", "prose", false},
		{"LICENSE", "prose", false},
		{"web/package-lock.json", "lockfile", false},
		{"yarn.lock", "lockfile", false},
		{"go.sum", "lockfile", false},
		{"config/app.json", "config", true},
		{"icon.svg", "vector", false},
		{"lib/x.so", "object", true},
		{"archive.tar.gz", "archive", true},
		{"src/main.zig", "", true},
		{"license.py", "", true}, // exact names only: a prefix never hides code
		{"Makefile", "", true},
		{".gitignore", "", true},
		{`dir\README.MD`, "prose", false},
	}
	for _, tt := range tests {
		f := formats.formatOf(tt.name)
		got := ""
		if f != 0 {
			got = f.String()
		}
		if got != tt.want || f.opened() != tt.opened {
			t.Errorf("formatOf(%q) = %q (opened %v), want %q (opened %v)", tt.name, got, f.opened(), tt.want, tt.opened)
		}
		if MaybeSource(tt.name) != tt.opened {
			t.Errorf("MaybeSource(%q) = %v, want %v", tt.name, !tt.opened, tt.opened)
		}
	}
}

func TestLooksBinary(t *testing.T) {
	image := Format(indexOf(formatNames, "image") + 1) //nolint:gosec // short list
	cut := strings.Repeat("a", binaryProbeBytes-1) + "é"
	tests := []struct {
		name    string
		format  Format
		content string
		want    bool
	}{
		{"empty", 0, "", false},
		{"text", 0, "x = 1\n", false},
		{"NUL in UTF-8 text, no format", 0, "x\x00", false},
		{"NUL in a non-UTF-8 head, no format", 0, "\x7fELF\x02\x01\x00\xff\xfe", true},
		{"NUL under an image name", image, "x\x00", true},
		{"NUL past the probe", 0, strings.Repeat("a", binaryProbeBytes) + "\x00", false},
		{"Latin-1 text, no format", 0, "caf\xe9\n", false},
		{"Latin-1 under an image name", image, "caf\xe9\n", true},
		{"UTF-8 under an image name", image, "<?php echo 1;\n", false},
		{"character cut at the probe", image, cut, false},
		{"empty image", image, "", false},
	}
	for _, tt := range tests {
		if got := looksBinary(tt.format, []byte(tt.content)); got != tt.want {
			t.Errorf("%s: looksBinary = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestParseFormatsRejects(t *testing.T) {
	for _, row := range []string{
		"ext .png",
		"ext .png picture",
		"suffix .png image",
		"ext .PNG image",
		"glob *.a*b image",
		"glob nostar image",
		"ext .png image\next .png font",
		"name license prose\nname license data",
	} {
		if _, err := parseFormats(row); err == nil {
			t.Errorf("parseFormats(%q) accepted a broken row", row)
		}
	}
}

// The format table names formats only (#366): no row's pattern is an
// extension the inventory labels as a language, so no language is ever
// left unread by name.
func TestFormatsNameNoLanguage(t *testing.T) {
	formats, err := loadFormats()
	if err != nil {
		t.Fatal(err)
	}
	inv, err := loadInventory()
	if err != nil {
		t.Fatal(err)
	}
	for ext := range formats.exts {
		if e, ok := inv.exact[matchExt][ext]; ok && e.Language != 0 {
			t.Errorf("formats.txt leaves %s (%s) unread", ext, e.Language)
		}
	}
}

// TestReadsAsText (#380): only a file discovery reads whole as text counts
// toward the CLI's vendor bound; binary bytes, a NUL, a text format never
// opened and config (not_code when too large) do not.
func TestReadsAsText(t *testing.T) {
	tests := []struct {
		name string
		head string
		want bool
	}{
		{"app.zig", "pub fn main() void {}\n", true},
		{"logo.png", "text named like an image\n", true},
		{"logo.png", "\x89PNG\r\n\x1a\n\x00", false},
		{"pad.bin", strings.Repeat("\x00", 64), false},
		{"app.py", "x = 1\x00\n", false},
		{"notes.md", "# notes\n", false},
		{"settings.json", "{}\n", false},
		{"blob", "\xff\xfe\xfd\x00", false},
	}
	for _, tt := range tests {
		if got := ReadsAsText(tt.name, []byte(tt.head)); got != tt.want {
			t.Errorf("ReadsAsText(%q, %q) = %v, want %v", tt.name, tt.head, got, tt.want)
		}
	}
}
