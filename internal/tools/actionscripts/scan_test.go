package actionscripts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeCreep records its arguments, environment and the --changed and
// --baseline files it was given, writes $FAKE_REPORTS into .creep and exits
// with $FAKE_CODE.
const fakeCreep = `printf '%s\n' "$@" >"$FAKE_DIR/args"
env >"$FAKE_DIR/env"
for a in "$@"; do
  case "$a" in
    --changed=*) cp "${a#--changed=}" "$FAKE_DIR/changed" ;;
    --baseline=*) cp "${a#--baseline=}" "$FAKE_DIR/baseline" ;;
  esac
done
mkdir -p .creep
for f in ${FAKE_REPORTS-report.json report.sarif report.md}; do echo "$f" >".creep/$f"; done
exit "${FAKE_CODE:-0}"
`

func scanSandbox(t *testing.T) (*sandbox, string) {
	t.Helper()
	s := newSandbox(t)
	s.fake("creep", fakeCreep)
	dir := t.TempDir()
	s.env = map[string]string{"CREEP": filepath.Join(s.bin, "creep"), "FAKE_DIR": dir, "EVENT_NAME": "push",
		"NEED_SARIF": "true", "NEED_MARKDOWN": "true"}
	return s, dir
}

// Protection (ADR 0023, #29 auditor note): every creep exit code is
// recorded for the verdict step, so 4 can fail the job as 1 does, and only
// a run that wrote its reports (0, 1 or 4) publishes them: on 2 or 3 a
// report already sitting in .creep (planted by the repository) is never
// uploaded. A report the Action needs and creep did not write, or a link in
// its place, stops the Action.
func TestScanRecordsExitCodeAndReports(t *testing.T) {
	tests := []struct {
		name      string
		code      string
		reports   string
		plant     func(t *testing.T, workdir string)
		env       map[string]string
		wantCode  int
		want      string
		published bool
	}{
		{"clean", "0", "report.json report.sarif report.md", nil, nil, 0, "", true},
		{"gate exceeded", "1", "report.json report.sarif report.md", nil, nil, 0, "", true},
		{"incomplete", "4", "report.json report.sarif report.md", nil, nil, 0, "", true},
		{"config error ignores planted reports", "2", "", plantReports, nil, 0, "", false},
		{"model error ignores planted reports", "3", "", plantReports, nil, 0, "", false},
		{"needed SARIF missing", "0", "report.json report.md", nil, nil, 1, "wrote no .creep/report.sarif", false},
		{"needed Markdown missing", "1", "report.json report.sarif", nil, nil, 1, "wrote no .creep/report.md", false},
		{"SARIF not needed", "0", "report.json report.md", nil, map[string]string{"NEED_SARIF": "false"}, 0, "", true},
		{".creep is a link", "1", "", plantLinkedState, nil, 1, ".creep is not a directory", false},
		{"report is a link", "0", "report.json report.md", plantLinkedSARIF, nil, 1, "wrote no .creep/report.sarif", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, _ := scanSandbox(t)
			s.env["FAKE_CODE"], s.env["FAKE_REPORTS"] = tt.code, tt.reports
			for k, v := range tt.env {
				s.env[k] = v
			}
			if tt.plant != nil {
				tt.plant(t, s.workdir)
			}
			r := s.run("scan.sh")
			wantCode(t, r, tt.wantCode, tt.want)
			if r.outputs["exit-code"] != tt.code {
				t.Errorf("exit-code=%q, want %s", r.outputs["exit-code"], tt.code)
			}
			if got := r.outputs["report"] != ""; got != tt.published {
				t.Errorf("reports published: %v, want %v (%v)", got, tt.published, r.outputs)
			}
		})
	}
}

func plantReports(t *testing.T, workdir string) {
	for _, name := range []string{"report.json", "report.sarif", "report.md"} {
		mustWrite(t, filepath.Join(workdir, ".creep", name), "planted", 0o600)
	}
}

func plantLinkedState(t *testing.T, workdir string) {
	target := t.TempDir()
	plantReports(t, target)
	if err := os.Symlink(filepath.Join(target, ".creep"), filepath.Join(workdir, ".creep")); err != nil {
		t.Fatal(err)
	}
}

func plantLinkedSARIF(t *testing.T, workdir string) {
	target := filepath.Join(t.TempDir(), "planted.sarif")
	mustWrite(t, target, "planted", 0o600)
	mustWrite(t, filepath.Join(workdir, ".creep", "report.json"), "x", 0o600)
	if err := os.Symlink(target, filepath.Join(workdir, ".creep", "report.sarif")); err != nil {
		t.Fatal(err)
	}
}

// The inputs become flags in their = form, validated first; the model key
// reaches creep only as CREEP_API_KEY.
func TestScanArgs(t *testing.T) {
	tests := []struct {
		name     string
		env      map[string]string
		wantCode int
		want     string
		wantArgs string
	}{
		{"defaults", nil, 0, "", "scan\n"},
		{"config", map[string]string{"INPUT_CONFIG": "/etc/creep.yaml"}, 0, "", "scan\n--config=/etc/creep.yaml\n"},
		{"config starting with a dash", map[string]string{"INPUT_CONFIG": "-x"}, 0, "", "scan\n--config=-x\n"},
		{"mode nightly", map[string]string{"INPUT_MODE": "nightly"}, 0, "", "scan\n--mode=nightly\n"},
		{"mode pr", map[string]string{"INPUT_MODE": "pr"}, 0, "", "scan\n--mode=pr\n"},
		{"unknown mode", map[string]string{"INPUT_MODE": "nightly --replay"}, 1, "mode must be", ""},
		{"incremental off", map[string]string{"INPUT_INCREMENTAL": "false"}, 0, "", "scan\n"},
		{"incremental typo", map[string]string{"INPUT_INCREMENTAL": "yes"}, 1, "incremental must be", ""},
		{"incremental on push scans everything", map[string]string{"INPUT_INCREMENTAL": "true"}, 0, "", "scan\n"},
		{"upload-sarif not a boolean", map[string]string{"NEED_SARIF": "True"}, 1, "upload-sarif must be true or false", ""},
		{"comment not a boolean", map[string]string{"NEED_MARKDOWN": "yes"}, 1, "comment must be true or false", ""},
		{"empty comment switch", map[string]string{"NEED_MARKDOWN": ""}, 1, "comment must be true or false", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, dir := scanSandbox(t)
			for k, v := range tt.env {
				s.env[k] = v
			}
			r := s.run("scan.sh")
			wantCode(t, r, tt.wantCode, tt.want)
			if tt.wantCode == 0 && mustRead(t, filepath.Join(dir, "args")) != tt.wantArgs {
				t.Errorf("args %q, want %q", mustRead(t, filepath.Join(dir, "args")), tt.wantArgs)
			}
		})
	}
}

func TestScanPassesKeyOnlyAsCreepAPIKey(t *testing.T) {
	s, dir := scanSandbox(t)
	s.env["INPUT_API_KEY"] = "sk-test-key"
	wantCode(t, s.run("scan.sh"), 0, "")
	env := mustRead(t, filepath.Join(dir, "env"))
	if !strings.Contains(env, "CREEP_API_KEY=sk-test-key\n") || strings.Contains(env, "INPUT_API_KEY") {
		t.Errorf("creep environment holds the key wrongly:\n%s", env)
	}
}

// Protection (ADR 0023, ADR 0022): on a pull request the changed list comes
// from the base commit, and the baseline is read from the base commit, so
// an entry the pull request adds or edits never suppresses its own
// finding; a baseline only the pull request adds is not used at all.
func TestScanPullRequest(t *testing.T) {
	tests := []struct {
		name         string
		baseBaseline bool
		env          map[string]string
		wantCode     int
		want         string
		wantChanged  string // "" when --changed must be absent
		wantBaseline string // "" when --baseline must be absent
	}{
		{"changed files and base baseline", true, map[string]string{"INPUT_BASELINE": "creep-baseline.json"}, 0, "",
			"app.py\x00creep-baseline.json\x00new.py\x00", "base entries\n"},
		{"baseline only in the pull request", false, map[string]string{"INPUT_BASELINE": "creep-baseline.json"}, 0, "the base commit has no creep-baseline.json",
			"app.py\x00creep-baseline.json\x00new.py\x00", ""},
		{"incremental off", true, map[string]string{"INPUT_INCREMENTAL": "false"}, 0, "", "", ""},
		{"base commit not fetched", true, map[string]string{"BASE_SHA": strings.Repeat("1", 40)}, 1, "fetch-depth: 2", "", ""},
		{"base SHA with shell text", true, map[string]string{"BASE_SHA": "HEAD; id"}, 1, "no base commit SHA", "", ""},
		{"baseline outside the repository", true, map[string]string{"INPUT_BASELINE": "../creep-baseline.json"}, 1, "plain repository-relative path", "", ""},
		{"absolute baseline", true, map[string]string{"INPUT_BASELINE": "/tmp/b.json"}, 1, "plain repository-relative path", "", ""},
		{"baseline flag injection", true, map[string]string{"INPUT_BASELINE": "-x"}, 1, "plain repository-relative path", "", ""},
		{"baseline dot segment", true, map[string]string{"INPUT_BASELINE": "a/./b.json"}, 1, "plain repository-relative path", "", ""},
		{"baseline revision syntax", true, map[string]string{"INPUT_BASELINE": "HEAD:creep-baseline.json"}, 1, "plain repository-relative path", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, dir := scanSandbox(t)
			s.env["EVENT_NAME"] = "pull_request"
			s.env["BASE_SHA"] = pullRequestRepo(t, s.workdir, tt.baseBaseline)
			for k, v := range tt.env {
				s.env[k] = v
			}
			r := s.run("scan.sh")
			wantCode(t, r, tt.wantCode, tt.want)
			if tt.wantCode != 0 {
				return
			}
			checkPassedFile(t, dir, "changed", tt.wantChanged)
			checkPassedFile(t, dir, "baseline", tt.wantBaseline)
		})
	}
}

// pullRequestRepo makes a base commit and a pull request commit on top of
// it in dir, and returns the base SHA. The pull request edits app.py and
// the baseline (or adds it) and adds new.py.
func pullRequestRepo(t *testing.T, dir string, baseBaseline bool) string {
	t.Helper()
	git(t, dir, "init", "-q")
	mustWrite(t, filepath.Join(dir, "app.py"), "a = 1\n", 0o600)
	mustWrite(t, filepath.Join(dir, "same.py"), "b = 1\n", 0o600)
	if baseBaseline {
		mustWrite(t, filepath.Join(dir, "creep-baseline.json"), "base entries\n", 0o600)
	}
	git(t, dir, "add", ".")
	git(t, dir, "commit", "-q", "-m", "base")
	base := git(t, dir, "rev-parse", "HEAD")
	mustWrite(t, filepath.Join(dir, "app.py"), "a = 2\n", 0o600)
	mustWrite(t, filepath.Join(dir, "new.py"), "c = 1\n", 0o600)
	mustWrite(t, filepath.Join(dir, "creep-baseline.json"), "entries the pull request added\n", 0o600)
	git(t, dir, "add", ".")
	git(t, dir, "commit", "-q", "-m", "pull request")
	return base
}

func checkPassedFile(t *testing.T, dir, name, want string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, name)) //nolint:gosec // G304: the fake's own copy
	switch {
	case want == "" && err == nil:
		t.Errorf("--%s passed (%q), want none", name, data)
	case want != "" && string(data) != want:
		t.Errorf("--%s file %q, want %q (%v)", name, data, want, err)
	}
}

// Protection (ADR 0023 amendment): a merge group holds queued pull requests
// that are not on the base branch yet, so its baseline is read from the
// base commit as on a pull request; the changed list stays pull-request
// only, so a merge group scans everything.
func TestScanMergeGroupBaseline(t *testing.T) {
	s, dir := scanSandbox(t)
	s.env["EVENT_NAME"] = "merge_group"
	s.env["BASE_SHA"] = pullRequestRepo(t, s.workdir, true)
	s.env["INPUT_BASELINE"] = "creep-baseline.json"
	wantCode(t, s.run("scan.sh"), 0, "")
	checkPassedFile(t, dir, "baseline", "base entries\n")
	checkPassedFile(t, dir, "changed", "")

	s.env["BASE_SHA"] = ""
	wantCode(t, s.run("scan.sh"), 1, "no base commit SHA")
}

// Outside a pull request or merge group the baseline is the checkout's own
// file, and a missing one scans without it.
func TestScanBaselineOnPush(t *testing.T) {
	s, dir := scanSandbox(t)
	s.env["INPUT_BASELINE"] = "creep-baseline.json"
	wantCode(t, s.run("scan.sh"), 0, "scanning without a baseline")
	checkPassedFile(t, dir, "baseline", "")

	mustWrite(t, filepath.Join(s.workdir, "creep-baseline.json"), "main entries\n", 0o600)
	wantCode(t, s.run("scan.sh"), 0, "")
	if args := mustRead(t, filepath.Join(dir, "args")); args != "scan\n--baseline=creep-baseline.json\n" {
		t.Errorf("args %q", args)
	}
}

// Protection (v0.2 release pentest): creep scans the step's working
// directory, so the changed list and a base-commit baseline are read
// relative to it. Names relative to the repository root would match no
// walked file under a working-directory input, every changed file would be
// listed unchanged, and a pull request would pass on a scan that read
// nothing. Deleted files are left out, and an empty list (nothing changed
// in the working directory) scans every file instead (PR #307 review).
func TestScanWorkingDirectoryScope(t *testing.T) {
	tests := []struct {
		name        string
		edit        func(root string)
		want        string
		wantChanged string // "" when --changed must be absent
	}{
		{"change inside and outside", func(root string) {
			mustWrite(t, filepath.Join(root, "svc", "app.py"), "a = 2\n", 0o600)
			mustWrite(t, filepath.Join(root, "other.py"), "b = 2\n", 0o600)
		}, "", "app.py\x00"},
		{"change only outside", func(root string) {
			mustWrite(t, filepath.Join(root, "other.py"), "b = 2\n", 0o600)
		}, "scanning every file", ""},
		{"only a deletion", func(root string) {
			git(t, root, "rm", "-q", filepath.Join("svc", "old.py"))
		}, "scanning every file", ""},
		{"change and deletion", func(root string) {
			mustWrite(t, filepath.Join(root, "svc", "app.py"), "a = 2\n", 0o600)
			git(t, root, "rm", "-q", filepath.Join("svc", "old.py"))
		}, "", "app.py\x00"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, dir := scanSandbox(t)
			root := s.workdir
			base := workingDirectoryRepo(t, root, tt.edit)
			s.workdir = filepath.Join(root, "svc")
			s.env["EVENT_NAME"] = "pull_request"
			s.env["BASE_SHA"] = base
			s.env["INPUT_BASELINE"] = "creep-baseline.json"
			wantCode(t, s.run("scan.sh"), 0, tt.want)
			checkPassedFile(t, dir, "changed", tt.wantChanged)
			checkPassedFile(t, dir, "baseline", "svc entries\n")
		})
	}
}

// workingDirectoryRepo makes a base commit with a svc directory and a pull
// request commit from edit on top of it in root, and returns the base SHA.
func workingDirectoryRepo(t *testing.T, root string, edit func(root string)) string {
	t.Helper()
	git(t, root, "init", "-q")
	mustWrite(t, filepath.Join(root, "svc", "app.py"), "a = 1\n", 0o600)
	mustWrite(t, filepath.Join(root, "svc", "old.py"), "o = 1\n", 0o600)
	mustWrite(t, filepath.Join(root, "svc", "creep-baseline.json"), "svc entries\n", 0o600)
	mustWrite(t, filepath.Join(root, "creep-baseline.json"), "root entries\n", 0o600)
	git(t, root, "add", ".")
	git(t, root, "commit", "-q", "-m", "base")
	base := git(t, root, "rev-parse", "HEAD")
	edit(root)
	git(t, root, "add", "-A")
	git(t, root, "commit", "-q", "-m", "pull request")
	return base
}
