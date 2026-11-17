package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sneakercreepers/creep/internal/calibrate"
	"github.com/sneakercreepers/creep/internal/exitcode"
)

// Acceptance (#175): creep why prints a known finding's evidence, escaped;
// an unknown or malformed ID fails with exit 2 and an escaped message.
func TestWhy(t *testing.T) {
	cfg := scanRepo(t, map[string]string{"app.py": "@flask"}, "")
	m := &fakeModel{verdict: map[string]string{"sql_injection": "vulnerable", "ssrf": "inconclusive"}}
	if code, out, errOut := runScanWith(fakeDeps(m, calibrate.TierM), "scan", "--config", cfg); code != exitcode.Incomplete {
		t.Fatalf("scan exit %d\n%s\n%s", code, out, errOut)
	}
	tests := []struct {
		name     string
		args     []string
		wantCode int
		want     []string // in stdout for exit 0, stderr otherwise
		never    string   // must not appear in either stream
	}{
		{"probable finding", []string{"why", "sink-0"}, exitcode.OK,
			[]string{"finding sink-0", "status:     probable", "class:      sqli", "app.py:44", "confidence: 80/100", "evidence:   lines 44"}, ""},
		{"inconclusive finding", []string{"why", "sink-2"}, exitcode.OK, []string{"reason:     inconclusive", "evidence:   lines 61"}, ""},
		{"unknown ID", []string{"why", "sink-99"}, exitcode.ConfigError, []string{"no finding sink-99"}, ""},
		{"malformed ID", []string{"why", "sink\x1b[2J-0"}, exitcode.ConfigError, []string{`invalid finding ID "sink\x1b[2J-0"`}, "\x1b"},
		{"path-like ID", []string{"why", "../../etc/passwd"}, exitcode.ConfigError, []string{"invalid finding ID"}, ""},
		{"no ID", []string{"why"}, exitcode.ConfigError, []string{"want exactly one finding ID"}, ""},
		{"two IDs", []string{"why", "sink-0", "sink-1"}, exitcode.ConfigError, []string{"want exactly one finding ID"}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, out, errOut := runScanWith(noModelDeps, tt.args...)
			got := errOut
			if tt.wantCode == exitcode.OK {
				got = out
			}
			if code != tt.wantCode {
				t.Fatalf("exit %d, want %d\nstdout %q\nstderr %q", code, tt.wantCode, out, errOut)
			}
			for _, w := range tt.want {
				if !strings.Contains(got, w) {
					t.Errorf("output lacks %q:\n%s", w, got)
				}
			}
			if tt.never != "" && strings.Contains(out+errOut, tt.never) {
				t.Errorf("output holds %q unescaped: %q", tt.never, out+errOut)
			}
		})
	}
}

// A report planted or edited in .creep can only fail or print escaped
// text: why never echoes a repository string raw.
func TestWhyDistrustsTheReportFile(t *testing.T) {
	const planted = `{"schema_version":1,"tool":{"name":"creep","version":"x","commit":"y"},"run":{"incomplete":false},` +
		`"findings":[{"id":"f1","class":"sqli","status":"probable","path":"a\u001b]8;;http:evil\u0007.py","line":3}],` +
		`"coverage":{"classes":[],"not_evaluated":[]},"data_handling":{"requests":0,"bytes":0,"endpoints":[],"redactions":{}}}`
	tests := []struct {
		name     string
		content  string
		wantCode int
		want     string
	}{
		{"hostile path is escaped", planted, exitcode.OK, `a\x1b]8;;http:evil\x07.py:3`},
		{"unclean path refused", strings.Replace(planted, `http:evil`, `http://evil`, 1), exitcode.ConfigError, "invalid report input"}, // #177
		{"unknown field refused", strings.Replace(planted, `"line":3`, `"line":3,"cmd":"x"`, 1), exitcode.ConfigError, "invalid report input"},
		{"not JSON", "#!/bin/sh\n", exitcode.ConfigError, "invalid report input"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isolateUserConfig(t)
			t.Chdir(t.TempDir())
			if err := os.Mkdir(stateDir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(stateDir, "report.json"), []byte(tt.content), 0o600); err != nil {
				t.Fatal(err)
			}
			code, out, errOut := runScanWith(noModelDeps, "why", "f1")
			if code != tt.wantCode || !strings.Contains(out+errOut, tt.want) {
				t.Fatalf("exit %d, want %d and %q\nstdout %q\nstderr %q", code, tt.wantCode, tt.want, out, errOut)
			}
			if strings.ContainsAny(out+errOut, "\x1b\x07") {
				t.Fatalf("raw control bytes reached the terminal: %q", out+errOut)
			}
		})
	}
}

// Without a scan there is no report; why says so, exits 2, and creates
// nothing.
func TestWhyWithoutReport(t *testing.T) {
	isolateUserConfig(t)
	t.Chdir(t.TempDir())
	code, _, errOut := runScanWith(noModelDeps, "why", "sink-0")
	if code != exitcode.ConfigError || !strings.Contains(errOut, "no scan report") {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	if _, err := os.Lstat(stateDir); !os.IsNotExist(err) {
		t.Fatalf("why created %s: %v", stateDir, err)
	}
}
