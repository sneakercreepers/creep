package cli

import (
	"os"
	"path/filepath"
	"slices"
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

// TestChangedScope: only walked files the list names reach the scan; every
// other file that could be source is listed unchanged (by design); a
// listed path the walk never handed over (deleted, a directory, a link,
// under .git or .creep) is only counted, never scanned; the walk's own
// gaps stay.
func TestChangedScope(t *testing.T) {
	walked := repoFiles{
		paths: []string{"Makefile.bak.txt", "README.md", "app.py", "lib/util.py", "web/app.js"},
		gaps:  []report.NotEvaluated{{Path: "link.py", Reason: report.SkipNotRegular}, {Path: "node_modules/p/i.js", Reason: report.SkipVendor}},
	}
	list := &changedList{paths: map[string]bool{
		"web/app.js": true, "README.md": true, "deleted.py": true, "lib": true,
		".git/hooks/evil.py": true, ".creep/evil.py": true, "link.py": true,
	}}
	got, inc := list.scope(walked)
	if want := []string{"README.md", "web/app.js"}; !slices.Equal(got.paths, want) {
		t.Errorf("scanned %q, want %q", got.paths, want)
	}
	wantGaps := append(slices.Clone(walked.gaps),
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
