package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/sneakercreepers/creep/internal/gitindex"
	"github.com/sneakercreepers/creep/internal/report"
)

// TestParseChangedList: a list is one path per line or per NUL (git -z);
// blanks and repeats collapse; any entry no walked file can have fails the
// whole list, so a hostile or garbled list never scans a scope nobody
// chose.
func TestParseChangedList(t *testing.T) {
	tests := []struct {
		name    string
		data    string
		want    []string
		wantErr string
	}{
		{"empty list", "", nil, ""},
		{"lines", "app.py\nweb/app.js\n", []string{"app.py", "web/app.js"}, ""},
		{"CRLF lines", "app.py\r\nweb/app.js\r\n", []string{"app.py", "web/app.js"}, ""},
		{"blanks and repeats", "\napp.py\n\napp.py\r\n", []string{"app.py"}, ""},
		{"NUL-separated keeps a newline in a name", "odd\nname.py\x00b c.py\x00", []string{"b c.py", "odd\nname.py"}, ""},
		{"NUL-separated keeps a leading quote", "\"q.py\x00", []string{"\"q.py"}, ""},
		{"no trailing separator", "a.py", []string{"a.py"}, ""},
		{"parent escape", "app.py\n../outside.py\n", nil, "entry 2"},
		{"parent inside", "web/../app.py", nil, "not a clean path"},
		{"absolute Unix", "/etc/passwd", nil, "not a clean path"},
		{"drive letter", "C:/Windows/win.ini", nil, "not a clean path"},
		{"backslash", `web\app.js`, nil, "not a clean path"},
		{"UNC", `\\host\share\a.py`, nil, "not a clean path"},
		{"dot segment", "./app.py", nil, "not a clean path"},
		{"empty segment", "web//app.js", nil, "not a clean path"},
		{"trailing slash", "web/", nil, "not a clean path"},
		{"dot", ".", nil, "not a clean path"},
		{"dot dot", "..", nil, "not a clean path"},
		{"blank name in NUL list", "a.py\x00 \x00", []string{" ", "a.py"}, ""},
		{"git-quoted name", "\"caf\\303\\251.py\"\n", nil, "git's -z"},
		{"over the path cap", strings.Repeat("a", gitindex.MaxPathBytes+1), nil, "over 4096 bytes"},
		{"bad entry in NUL list", "a.py\x00../b.py\x00", nil, "entry 2"},
		{"one NUL makes the whole list NUL-separated", "a.py\nb.py\x00", []string{"a.py\nb.py"}, ""},
		{"CR kept in a NUL list", "a.py\r\x00", []string{"a.py\r"}, ""},
		{"case variants count once", "App.py\napp.py\nAPP.PY\n", []string{"app.py"}, ""},
		{"entry numbers count blanks", "a.py\n\n\n../b.py\n", nil, "entry 4"},
		{"bad entry after repeats", "a.py\na.py\r\n/etc/passwd\n", nil, "entry 3"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			list, err := parseChangedList([]byte(tt.data))
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			got := make([]string, 0, len(list.paths))
			for p := range list.paths {
				got = append(got, p)
			}
			slices.Sort(got)
			if !slices.Equal(got, tt.want) && (len(got) != 0 || len(tt.want) != 0) {
				t.Fatalf("paths = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestReadChangedList: the list file is opened as --config is: a missing
// file, a directory or one over the cap fails before anything is scanned.
func TestReadChangedList(t *testing.T) {
	dir := t.TempDir()
	ok := filepath.Join(dir, "ok.txt")
	big := filepath.Join(dir, "big.txt")
	writeFile(t, ok, "app.py\n")
	writeFile(t, big, strings.Repeat("a.py\n", maxChangedBytes/5+1))
	tests := []struct {
		name, path, wantErr string
	}{
		{"regular file", ok, ""},
		{"missing", filepath.Join(dir, "none.txt"), "does not exist"},
		{"directory", dir, "is a directory"},
		{"over the cap", big, "larger than"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			list, err := readChangedList(tt.path)
			if tt.wantErr == "" {
				if err != nil || !list.paths["app.py"] {
					t.Fatalf("list %v, err %v", list, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want %q", err, tt.wantErr)
			}
		})
	}
	if list, err := readChangedList(""); list != nil || err != nil {
		t.Fatalf("no flag: list %v, err %v; want a full scan", list, err)
	}
}

// sizedInfo is a FileInfo whose size the test chooses.
type sizedInfo struct {
	os.FileInfo
	size int64
}

func (s sizedInfo) Size() int64 { return s.size }

// Protection (#26, R22): a file that reads more or fewer bytes than its
// stat said (virtual, or rewritten while read) is refused, for the list as
// for --config.
func TestReadCappedFileRefusesSizeChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "changed.txt")
	writeFile(t, path, "app.py\n")
	for _, size := range []int64{0, 3, 100} {
		open := func(label, p string) (*os.File, os.FileInfo, error) {
			f, info, err := openConfig(label, p)
			return f, sizedInfo{info, size}, err
		}
		_, err := readCappedFile(open, "--changed", path, maxChangedBytes)
		if err == nil || !strings.Contains(err.Error(), "size changed while reading") {
			t.Errorf("stat size %d: err = %v, want a size refusal", size, err)
		}
	}
}

// Protection (#26): a list at the cap made of one repeated entry checks and
// copies it once, so a garbled list costs no more than its own bytes.
func TestParseChangedListRepeatsAreCheap(t *testing.T) {
	data := []byte(strings.Repeat("web/app.js\n", maxChangedBytes/11))
	allocs := testing.AllocsPerRun(1, func() {
		if _, err := parseChangedList(data); err != nil {
			t.Fatal(err)
		}
	})
	if allocs > 8 {
		t.Fatalf("%v allocations for one repeated entry, want a few", allocs)
	}
}

// BenchmarkParseChangedList is the documented worst case: a list at the
// 16 MiB cap of distinct short paths.
func BenchmarkParseChangedList(b *testing.B) {
	var buf bytes.Buffer
	for i := 0; buf.Len() < maxChangedBytes-16; i++ {
		buf.WriteString(strconv.Itoa(i))
		buf.WriteByte(0)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := parseChangedList(buf.Bytes()); err != nil {
			b.Fatal(err)
		}
	}
}

// Case variants (#26): a walked name that differs from a listed one only
// in case is scanned too, so a case-insensitive disk spelling a name
// otherwise than git's index never turns a changed file into an unchanged
// one; a listed name no walked file folds to stays missing.
func TestChangedScopeFoldsCase(t *testing.T) {
	walked := repoFiles{paths: []string{"App.py", "app.py", "lib/Util.py", "web/app.js"}}
	list, err := parseChangedList([]byte("APP.PY\nLIB/util.py\ngone.py\n"))
	if err != nil {
		t.Fatal(err)
	}
	got, inc := list.scope(walked)
	if want := []string{"App.py", "app.py", "lib/Util.py"}; !slices.Equal(got.paths, want) {
		t.Errorf("scanned %q, want %q", got.paths, want)
	}
	if want := []report.NotEvaluated{{Path: "web/app.js", Reason: report.SkipUnchanged}}; !slices.Equal(got.gaps, want) {
		t.Errorf("gaps %v, want %v", got.gaps, want)
	}
	if want := (report.Incremental{On: true, Listed: 3, Missing: 1}); inc != want {
		t.Errorf("scope %+v, want %+v", inc, want)
	}
}

// TestChangedScope: only walked files the list names reach the scan; every
// other file is listed unchanged (by design, #366); a
// listed path the walk never handed over (deleted, a directory, a link,
// under .git or .creep) is only counted, never scanned; the walk's own
// gaps stay.
func TestChangedScope(t *testing.T) {
	walked := repoFiles{
		paths: []string{"Makefile.bak.txt", "README.md", "app.py", "lib/util.py", "web/app.js"},
		gaps:  []report.NotEvaluated{{Path: "link.py", Reason: report.SkipNotRegular}, {Path: "node_modules/p/i.js", Reason: report.SkipVendor}},
	}
	list, err := parseChangedList([]byte("web/app.js\x00README.md\x00deleted.py\x00lib\x00.git/hooks/evil.py\x00.creep/evil.py\x00link.py\x00"))
	if err != nil {
		t.Fatal(err)
	}
	got, inc := list.scope(walked)
	if want := []string{"README.md", "web/app.js"}; !slices.Equal(got.paths, want) {
		t.Errorf("scanned %q, want %q", got.paths, want)
	}
	wantGaps := append(slices.Clone(walked.gaps),
		report.NotEvaluated{Path: "Makefile.bak.txt", Reason: report.SkipUnchanged},
		report.NotEvaluated{Path: "app.py", Reason: report.SkipUnchanged},
		report.NotEvaluated{Path: "lib/util.py", Reason: report.SkipUnchanged})
	if !slices.Equal(got.gaps, wantGaps) {
		t.Errorf("gaps %v, want %v", got.gaps, wantGaps)
	}
	if want := (report.Incremental{On: true, Listed: 7, Missing: 5}); inc != want {
		t.Errorf("scope %+v, want %+v", inc, want)
	}
	if !slices.Equal(walked.paths, []string{"Makefile.bak.txt", "README.md", "app.py", "lib/util.py", "web/app.js"}) || len(walked.gaps) != 2 {
		t.Errorf("scope changed the walk's own files: %+v", walked)
	}
	full, inc := (*changedList)(nil).scope(walked)
	if !slices.Equal(full.paths, walked.paths) || !slices.Equal(full.gaps, walked.gaps) || inc.On {
		t.Errorf("no list: %+v %+v, want the whole walk", full, inc)
	}
}

func writeFile(t *testing.T, path, data string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}
