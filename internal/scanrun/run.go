package scanrun

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/sneakercreepers/creep/internal/static"
)

// Outcome is what running one scanner gave.
type Outcome uint8

// Outcomes. Only Evaluated means the scanner's classes were evaluated.
const (
	NotRun    Outcome = iota // never started: no offline mode for it
	Refused                  // the binary or its database is in the repository or the working directory, or is not an .exe on Windows
	Failed                   // started but evaluated nothing; the run is incomplete
	Evaluated                // ran and its report was read in full
)

// Failure is why a started scanner evaluated nothing, a closed set.
type Failure uint8

// Failures.
const (
	FailNone      Failure = iota
	FailStart             // the program or its temporary directory could not be set up or started
	FailTimeout           // it ran past Limits.Timeout
	FailExit              // it exited with a status that is not success
	FailTooLarge          // its report passed Limits.MaxOutput
	FailMalformed         // its report is missing or does not decode
	FailPath              // a finding names a path outside the repository
	FailTooMany           // more than Limits.MaxFindings findings
)

var failureNames = [...]string{"none", "start_failed", "timeout", "exit_status", "output_too_large", "malformed_output", "path_outside_repo", "too_many_findings"}

// String is the failure as an ID, safe to print.
func (f Failure) String() string {
	if int(f) < len(failureNames) {
		return failureNames[f]
	}
	return "unknown"
}

// Finding is one result. Path is repository-relative and slash-separated;
// Line is 1-based, 0 for the whole file. Key is a hex digest of the
// scanner, path, line and the tool's rule or advisory: an ID, never tool text.
type Finding struct {
	Path string
	Line int
	Key  string
}

// Result is one scanner run.
type Result struct {
	Outcome  Outcome
	Failure  Failure
	Findings []Finding
}

// Limits bound one run.
type Limits struct {
	Timeout     time.Duration
	MaxOutput   int64 // report bytes
	MaxFindings int
}

// DefaultLimits are the limits creep scan uses.
func DefaultLimits() Limits {
	return Limits{Timeout: 10 * time.Minute, MaxOutput: 64 << 20, MaxFindings: 10_000}
}

// Job is one scanner to run. Bin is the final path from
// static.DetectScanners; Repo the absolute repository root; OSVDB the
// user's offline osv-scanner database directory, empty when none.
type Job struct {
	Scanner static.Scanner
	Bin     string
	Repo    string
	OSVDB   string
	Limits  Limits
}

// Run runs job's scanner if it has an offline mode and its binary may run.
func Run(ctx context.Context, job Job) Result {
	tool, ok := toolFor(job)
	if !ok {
		return Result{Outcome: NotRun}
	}
	bin, ok := static.OutsideRepo(job.Bin, job.Repo)
	if !ok || !runnableName(bin) {
		return Result{Outcome: Refused}
	}
	if job.OSVDB != "" {
		if _, ok := static.OutsideRepo(job.OSVDB, job.Repo); !ok {
			return Result{Outcome: Refused}
		}
	}
	return execute(ctx, job, tool, bin)
}

// toolFor picks the scanner's fixed invocation; semgrep, and osv-scanner
// without a local database, have no offline mode creep can use.
func toolFor(job Job) (tool, bool) {
	switch job.Scanner {
	case static.ScannerGitleaks:
		return gitleaks, true
	case static.ScannerOSV:
		return osvScanner, job.OSVDB != "" && filepath.IsAbs(job.OSVDB)
	}
	return tool{}, false
}

// runnableName refuses anything but an .exe on Windows: CreateProcess runs
// a .bat or .cmd through cmd.exe, which would parse the arguments.
func runnableName(bin string) bool {
	return runtime.GOOS != "windows" || strings.EqualFold(filepath.Ext(bin), ".exe")
}

// execute runs the tool in a fresh temporary directory and reads its report.
func execute(ctx context.Context, job Job, t tool, bin string) Result {
	tmp, err := newWorkspace(t)
	if err != nil {
		return failed(FailStart)
	}
	defer os.RemoveAll(tmp.root)
	ctx, cancel := context.WithTimeout(ctx, job.Limits.Timeout)
	defer cancel()
	// G204: bin is a final path outside the repository, args are fixed
	// per tool, and no shell is involved (ADR 0013).
	cmd := exec.CommandContext(ctx, bin, t.args(tmp, job.Repo)...) //nolint:gosec // G204, see above
	cmd.Dir, cmd.Env = tmp.work, environment(tmp, job)
	cmd.WaitDelay = time.Second
	err = cmd.Run()
	if ctx.Err() != nil {
		return failed(FailTimeout)
	}
	code, ok := exitCode(err)
	if !ok {
		return failed(FailStart)
	}
	if slices.Contains(t.emptyExits, code) {
		return Result{Outcome: Evaluated}
	}
	if !slices.Contains(t.okExits, code) {
		return failed(FailExit)
	}
	return readReport(tmp.report, job, t)
}

// exitCode is the process exit status; ok is false when it never started.
func exitCode(err error) (int, bool) {
	var exit *exec.ExitError
	switch {
	case err == nil:
		return 0, true
	case errors.As(err, &exit):
		return exit.ExitCode(), true
	}
	return 0, false
}

// readReport reads at most Limits.MaxOutput bytes of the report and parses it.
func readReport(path string, job Job, t tool) Result {
	data, failure := readCapped(path, job.Limits.MaxOutput)
	if failure != FailNone {
		return failed(failure)
	}
	findings, failure := t.parse(data, job.Repo, job.Limits.MaxFindings)
	if failure != FailNone {
		return failed(failure)
	}
	return Result{Outcome: Evaluated, Findings: findings}
}

func readCapped(path string, max int64) ([]byte, Failure) {
	f, err := os.Open(path)
	if err != nil {
		return nil, FailMalformed
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	switch {
	case err != nil:
		return nil, FailMalformed
	case int64(len(data)) > max:
		return nil, FailTooLarge
	}
	return data, FailNone
}

func failed(f Failure) Result { return Result{Outcome: Failed, Failure: f} }

// workspace is the temporary directory one run owns.
type workspace struct {
	root, home, tmp, work, report, config, ignore string
}

// newWorkspace creates the directories and writes the tool's fixed config.
func newWorkspace(t tool) (workspace, error) {
	root, err := os.MkdirTemp("", "creep-scanner-")
	if err != nil {
		return workspace{}, fmt.Errorf("scanner workspace: %w", err)
	}
	w := workspace{
		root: root, home: filepath.Join(root, "home"), tmp: filepath.Join(root, "tmp"),
		work: filepath.Join(root, "work"), ignore: filepath.Join(root, "ignore"),
		report: filepath.Join(root, "report.json"), config: filepath.Join(root, t.configName),
	}
	for _, dir := range []string{w.home, w.tmp, w.work, w.ignore} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			os.RemoveAll(root)
			return workspace{}, fmt.Errorf("scanner workspace: %w", err)
		}
	}
	if err := os.WriteFile(w.config, []byte(t.config), 0o600); err != nil {
		os.RemoveAll(root)
		return workspace{}, fmt.Errorf("scanner workspace: %w", err)
	}
	return w, nil
}

// blackholeProxy is a loopback port nothing should serve: a tool that
// tries HTTP despite its offline flag gets a refused connection.
const blackholeProxy = "http://127.0.0.1:1"

// environment is the whole environment of the child: nothing of creep's
// is inherited (no CREEP_API_KEY, tokens, proxies or PATH). Windows adds
// SYSTEMROOT itself (os/exec).
func environment(w workspace, job Job) []string {
	env := []string{"PATH=", "NO_PROXY=", "no_proxy="}
	for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		env = append(env, k+"="+blackholeProxy)
	}
	for _, k := range []string{"HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME"} {
		env = append(env, k+"="+w.home)
	}
	for _, k := range []string{"TMPDIR", "TMP", "TEMP"} {
		env = append(env, k+"="+w.tmp)
	}
	if job.Scanner == static.ScannerOSV {
		env = append(env, "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY="+job.OSVDB)
	}
	return env
}
