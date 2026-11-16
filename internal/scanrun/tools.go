package scanrun

import (
	"os"
	"path/filepath"
)

// tool is one scanner's fixed invocation: the config creep writes for it,
// its argument list (the repository is the only variable), the exit
// statuses that mean success or "nothing to scan", its report parser, and
// a check for repository files that would suppress its results whatever
// the flags say.
type tool struct {
	configName, config string
	args               func(w workspace, repo string) []string
	okExits            []int // success; the report is read
	emptyExits         []int // success with nothing to scan; no report
	parse              func(data []byte, repo string, max int) ([]Finding, Failure)
	repoSuppresses     func(repo string) bool
}

// gitleaks scans files only (--no-git: no history, no git binary) with
// creep's config, which extends the built-in rules, so a repository's
// .gitleaks.toml cannot replace them. --redact keeps secrets out of the
// report, and --exit-code 0 makes any other status a failure. gitleaks
// always loads <source>/.gitleaksignore, whatever --gitleaks-ignore-path
// says, so a repository with one is not scanned: the run is failed and
// incomplete rather than silently filtered. Inline gitleaks:allow comments
// still apply (ADR 0013).
var gitleaks = tool{
	configName: "gitleaks.toml",
	config:     "title = \"creep: gitleaks built-in rules\"\n\n[extend]\nuseDefault = true\n",
	args: func(w workspace, repo string) []string {
		return []string{
			"detect", "--no-git", "--source", repo,
			"--config", w.config, "--gitleaks-ignore-path", w.ignore,
			"--report-format", "json", "--report-path", w.report,
			"--redact", "--no-banner", "--log-level", "error", "--exit-code", "0",
		}
	},
	okExits:        []int{0},
	parse:          parseGitleaks,
	repoSuppresses: hasGitleaksIgnore,
}

// hasGitleaksIgnore reports a .gitleaksignore at the repository root, of
// any type (a link or directory included), or one creep cannot rule out.
func hasGitleaksIgnore(repo string) bool {
	_, err := os.Lstat(filepath.Join(repo, ".gitleaksignore"))
	return !os.IsNotExist(err)
}

// osvScanner (v2) checks lockfiles against the user's local database only:
// --offline turns off every network feature (no database download, no
// registry resolution). An empty --config replaces any osv-scanner.toml in
// the repository, so it cannot ignore advisories, and --no-ignore scans
// files its .gitignore lists. Exit 1 means advisories were found, 128 that
// there was nothing to scan.
var osvScanner = tool{
	configName: "osv-scanner.toml",
	config:     "# creep: no ignored advisories\n",
	args: func(w workspace, repo string) []string {
		return []string{
			"scan", "source", "--recursive", "--no-ignore", "--offline",
			"--config", w.config, "--format", "json", "--output", w.report,
			repo,
		}
	},
	okExits:    []int{0, 1},
	emptyExits: []int{128},
	parse:      parseOSV,
}
