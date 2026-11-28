package cli

import (
	"slices"
	"strings"
	"testing"

	"github.com/sneakercreepers/creep/internal/calibrate"
	"github.com/sneakercreepers/creep/internal/exitcode"
	"github.com/sneakercreepers/creep/internal/redact"
	"github.com/sneakercreepers/creep/internal/report"
)

// Protection (#366): exit 0 never hides an unread text file. Every text
// file, in any language and under any name the format list does not name,
// is sent to discovery whole; every other file is listed with a by-design
// reason; and a text file that cannot be read in full, whatever its
// language, makes the run exit 4 with the file listed.
func TestExitZeroNeverHidesUnreadText(t *testing.T) {
	text := map[string]string{
		"main.py": helloRoute, "src/main.zig": "pub fn main() void {}\n", "src/server.nim": "proc main() = discard\n",
		"Makefile": "all:\n\tcc x.c\n", "deploy.sh": "echo hi\n", "assets/fake.png": "<?php echo 1;\n", "bin/tool": "run\n",
		"data.json": "{}\n",
	}
	listed := map[string]report.SkipReason{
		"README.md": report.SkipNotCode, "LICENSE": report.SkipNotCode, "yarn.lock": report.SkipNotCode,
		"assets/logo.png": report.SkipBinary, "blob": report.SkipBinary,
	}
	files := map[string]string{"README.md": "# x\n", "LICENSE": "text\n", "yarn.lock": "x\n", "assets/logo.png": "\x89PNG\r\n\x1a\n\x00", "blob": "a\x00b\xff"}
	for name, src := range text {
		files[name] = src
	}
	cfg := scanRepo(t, files, "")
	code, out, errOut := runScanWith(fakeDeps(&fakeModel{}, calibrate.TierM), "scan", "--config", cfg)
	if code != exitcode.OK {
		t.Fatalf("exit %d, want 0\n%s\n%s", code, out, errOut)
	}
	if want := "discovery: 8 whole source files sent"; !strings.Contains(out, want) {
		t.Errorf("output lacks %q: every text file must be sent\n%s", want, out)
	}
	rep, err := readLastReport()
	if err != nil {
		t.Fatal(err)
	}
	var want []report.NotEvaluated
	for p, r := range listed {
		want = append(want, report.NotEvaluated{Path: p, Reason: r})
	}
	slices.SortFunc(want, func(a, b report.NotEvaluated) int { return strings.Compare(a.Path, b.Path) })
	got := slices.Clone(rep.Coverage.NotEvaluated)
	slices.SortFunc(got, func(a, b report.NotEvaluated) int { return strings.Compare(a.Path, b.Path) })
	if !slices.Equal(got, want) {
		t.Errorf("not evaluated = %+v, want %+v", got, want)
	}
}

// The other half of the protection: a text file no inventory row names
// that discovery cannot read in full is listed, and the run exits 4, never
// 0. A text file with a NUL, labeled or not, is read_failed, never binary.
func TestUnreadTextFailsTheRun(t *testing.T) {
	big := strings.Repeat("const x = 1;\n", redact.MaxFileBytes/12)
	tests := []struct {
		name, file, src string
		reason          report.SkipReason
	}{
		{"oversized text in any language", "src/big.zig", big, report.SkipTooLarge},
		{"over one call", "src/mid.nim", strings.Repeat("proc a() = discard\n", 3000), report.SkipTooLarge},
		{"UTF-16 text", "src/w.ps1", "\xff\xfeo\x00s\x00", report.SkipReadFailed},
		{"labeled source with a NUL", "app.js", "// \x00\nexec(x)\n", report.SkipReadFailed},
		{"text in any language with a NUL", "src/main.zig", "pub fn main() void {}\n\x00", report.SkipReadFailed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := scanRepo(t, map[string]string{"main.py": helloRoute, tt.file: tt.src}, "")
			code, out, errOut := runScanWith(fakeDeps(&fakeModel{}, calibrate.TierM), "scan", "--config", cfg)
			if code != exitcode.Incomplete || !strings.Contains(out, tt.file+"  "+string(tt.reason)) {
				t.Fatalf("exit %d, want 4 with %s listed %s\n%s\n%s", code, tt.file, tt.reason, out, errOut)
			}
		})
	}
}
