package scanrun

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sneakercreepers/creep/internal/static"
)

// osvDB lays out a local osv-scanner database under dir, as
// --download-offline-databases would, and returns dir.
func osvDB(t *testing.T, dir string) string {
	t.Helper()
	writeFile(t, filepath.Join(dir, "osv-scanner", "npm", "all.zip"), "PK fake")
	return dir
}

func writeFile(t *testing.T, path, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}

func testLimits() Limits {
	return Limits{Timeout: 20 * time.Second, MaxOutput: 1024, MaxFindings: 10}
}

// TestRun drives the runner against fake scanners: what a good report
// gives, and every way a run fails closed. CREEP_API_KEY is set so the
// fake can prove it never reaches the child.
func TestRun(t *testing.T) {
	t.Setenv("CREEP_API_KEY", "sk-test-must-not-leak")
	tests := []struct {
		name     string
		scanner  static.Scanner
		mode     string
		limits   func(*Limits)
		want     Outcome
		failure  Failure
		findings int
	}{
		{"gitleaks findings, deduplicated", static.ScannerGitleaks, "findings", nil, Evaluated, FailNone, 2},
		{"osv-scanner advisories with exit 1", static.ScannerOSV, "findings", nil, Evaluated, FailNone, 2},
		{"osv-scanner nothing to scan (exit 128)", static.ScannerOSV, "empty", nil, Evaluated, FailNone, 0},
		{"malformed report", static.ScannerGitleaks, "malformed", nil, Failed, FailMalformed, 0},
		{"missing report", static.ScannerGitleaks, "noreport", nil, Failed, FailMalformed, 0},
		{"report over the byte cap", static.ScannerGitleaks, "huge", nil, Failed, FailTooLarge, 0},
		{"more findings than the cap", static.ScannerGitleaks, "findings", func(l *Limits) { l.MaxFindings = 1 }, Failed, FailTooMany, 0},
		{"path outside the repository", static.ScannerGitleaks, "outside", nil, Failed, FailPath, 0},
		{"non-zero exit", static.ScannerGitleaks, "exit3", nil, Failed, FailExit, 0},
		{"timeout", static.ScannerOSV, "slow", func(l *Limits) { l.Timeout = 500 * time.Millisecond }, Failed, FailTimeout, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			base := t.TempDir()
			repo := filepath.Join(base, "repo")
			if err := os.Mkdir(repo, 0o700); err != nil {
				t.Fatal(err)
			}
			job := Job{Scanner: tc.scanner, Bin: installFake(t, base, tc.mode, string(tc.scanner)), Repo: repo, OSVDB: osvDB(t, t.TempDir()), Limits: testLimits()}
			if tc.limits != nil {
				tc.limits(&job.Limits)
			}
			start := time.Now()
			got := Run(context.Background(), job)
			if got.Outcome != tc.want || got.Failure != tc.failure || len(got.Findings) != tc.findings {
				t.Fatalf("Run = %+v, want outcome %d, failure %s, %d findings", got, tc.want, tc.failure, tc.findings)
			}
			if time.Since(start) > 15*time.Second {
				t.Errorf("run took %v", time.Since(start))
			}
			checkFindings(t, got.Findings)
		})
	}
}

func checkFindings(t *testing.T, findings []Finding) {
	t.Helper()
	for _, f := range findings {
		if f.Path != "app/config.py" && f.Path != "package-lock.json" {
			t.Errorf("finding path %q, want repository-relative", f.Path)
		}
		if len(f.Key) != 24 {
			t.Errorf("finding key %q is not a 24-digit hex ID", f.Key)
		}
	}
}

// TestRunRefusesWithoutStarting covers the cases where nothing may start:
// no offline mode (semgrep, osv-scanner without a local database), a binary
// or database in the repository, and a relative or missing repository.
func TestRunRefusesWithoutStarting(t *testing.T) {
	tests := []struct {
		name string
		job  func(t *testing.T, base, repo string) Job
		want Outcome
	}{
		{"semgrep has no offline rules", func(t *testing.T, base, repo string) Job {
			return Job{Scanner: static.ScannerSemgrep, Bin: installFake(t, base, "findings", "semgrep"), Repo: repo}
		}, NotRun},
		{"osv-scanner without a local database would go online", func(t *testing.T, base, repo string) Job {
			return Job{Scanner: static.ScannerOSV, Bin: installFake(t, base, "findings", "osv-scanner"), Repo: repo}
		}, NotRun},
		{"osv-scanner with a relative database path", func(t *testing.T, base, repo string) Job {
			return Job{Scanner: static.ScannerOSV, Bin: installFake(t, base, "findings", "osv-scanner"), Repo: repo, OSVDB: "db"}
		}, NotRun},
		{"osv-scanner with an empty database directory", func(t *testing.T, base, repo string) Job {
			return Job{Scanner: static.ScannerOSV, Bin: installFake(t, base, "findings", "osv-scanner"), Repo: repo, OSVDB: t.TempDir()}
		}, NotRun},
		{"osv-scanner with only an empty all.zip", func(t *testing.T, base, repo string) Job {
			db := t.TempDir()
			writeFile(t, filepath.Join(db, "osv-scanner", "npm", "all.zip"), "")
			return Job{Scanner: static.ScannerOSV, Bin: installFake(t, base, "findings", "osv-scanner"), Repo: repo, OSVDB: db}
		}, NotRun},
		{"osv-scanner with a missing database directory", func(t *testing.T, base, repo string) Job {
			return Job{Scanner: static.ScannerOSV, Bin: installFake(t, base, "findings", "osv-scanner"), Repo: repo, OSVDB: filepath.Join(base, "none")}
		}, NotRun},
		{"gitleaks with a repository .gitleaksignore", func(t *testing.T, base, repo string) Job {
			writeFile(t, filepath.Join(repo, ".gitleaksignore"), "app/config.py:generic-api-key:3\n")
			return Job{Scanner: static.ScannerGitleaks, Bin: installFake(t, base, "findings", "gitleaks"), Repo: repo}
		}, Failed},
		{"gitleaks with a .gitleaksignore directory", func(t *testing.T, base, repo string) Job {
			if err := os.Mkdir(filepath.Join(repo, ".gitleaksignore"), 0o700); err != nil {
				t.Fatal(err)
			}
			return Job{Scanner: static.ScannerGitleaks, Bin: installFake(t, base, "findings", "gitleaks"), Repo: repo}
		}, Failed},
		{"osv-scanner database inside the repository", func(t *testing.T, base, repo string) Job {
			return Job{Scanner: static.ScannerOSV, Bin: installFake(t, base, "findings", "osv-scanner"), Repo: repo, OSVDB: osvDB(t, repo)}
		}, Refused},
		{"binary inside the repository", func(t *testing.T, _, repo string) Job {
			return Job{Scanner: static.ScannerGitleaks, Bin: installFake(t, repo, "findings", "gitleaks"), Repo: repo}
		}, Refused},
		{"relative repository", func(t *testing.T, base, _ string) Job {
			return Job{Scanner: static.ScannerGitleaks, Bin: installFake(t, base, "findings", "gitleaks"), Repo: "repo"}
		}, Refused},
		{"unknown scanner", func(t *testing.T, base, repo string) Job {
			return Job{Scanner: "curl", Bin: installFake(t, base, "findings", "curl"), Repo: repo}
		}, NotRun},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			base := t.TempDir()
			repo := filepath.Join(base, "repo")
			if err := os.Mkdir(repo, 0o700); err != nil {
				t.Fatal(err)
			}
			job := tc.job(t, base, repo)
			job.Limits = testLimits()
			got := Run(context.Background(), job)
			if got.Outcome != tc.want || len(got.Findings) != 0 {
				t.Fatalf("Run = %+v, want outcome %d", got, tc.want)
			}
			if tc.want == Failed && got.Failure != FailRepoIgnore {
				t.Errorf("failure %s, want %s", got.Failure, FailRepoIgnore)
			}
			if ran(job.Bin) {
				t.Error("the binary was started")
			}
		})
	}
}

func TestRepoRelative(t *testing.T) {
	repo := filepath.Join(t.TempDir(), "repo")
	tests := []struct {
		path, want string
		ok         bool
	}{
		{filepath.Join(repo, "a", "b.py"), "a/b.py", true},
		{"a/b.py", "a/b.py", true},
		{filepath.Join(repo, "a", "..", "b.py"), "b.py", true},
		{"", "", false},
		{repo, "", false},
		{filepath.Join(repo, "..", "x.py"), "", false},
		{"../x.py", "", false},
		{filepath.Join(repo+"2", "x.py"), "", false},
		{"bad\xffname", "", false},
	}
	for _, tc := range tests {
		got, ok := repoRelative(tc.path, repo)
		if got != tc.want || ok != tc.ok {
			t.Errorf("repoRelative(%q) = %q, %v; want %q, %v", tc.path, got, ok, tc.want, tc.ok)
		}
	}
}

func TestParseRejectsHostileReports(t *testing.T) {
	repo := filepath.Join(t.TempDir(), "repo")
	tests := map[string]struct {
		parse func([]byte, string, int) ([]Finding, Failure)
		data  string
		want  Failure
	}{
		"gitleaks object instead of array": {parseGitleaks, `{"File":"a"}`, FailMalformed},
		"gitleaks trailing data":           {parseGitleaks, `[] []`, FailMalformed},
		"gitleaks negative line":           {parseGitleaks, `[{"File":"a.py","StartLine":-1}]`, FailMalformed},
		"gitleaks huge line":               {parseGitleaks, `[{"File":"a.py","StartLine":99999999999}]`, FailMalformed},
		"gitleaks empty file name":         {parseGitleaks, `[{"File":"","StartLine":1}]`, FailPath},
		"gitleaks null is no findings":     {parseGitleaks, `null`, FailNone},
		"osv wrong type":                   {parseOSV, `{"results":"x"}`, FailMalformed},
		"osv source outside":               {parseOSV, `{"results":[{"source":{"path":"../go.sum"},"packages":[{"vulnerabilities":[{"id":"GO-1"}]}]}]}`, FailPath},
		"osv no vulnerabilities":           {parseOSV, `{"results":[{"source":{"path":"../go.sum"},"packages":[{"vulnerabilities":[]}]}]}`, FailNone},
	}
	for name, tc := range tests {
		if _, got := tc.parse([]byte(tc.data), repo, 10); got != tc.want {
			t.Errorf("%s: failure %s, want %s", name, got, tc.want)
		}
	}
}
