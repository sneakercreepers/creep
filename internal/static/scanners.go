package static

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Scanner is an optional external scanner, named as in config
// scanners.enabled.
type Scanner string

// The optional scanners, in report order.
const (
	ScannerGitleaks Scanner = "gitleaks"
	ScannerOSV      Scanner = "osv-scanner"
	ScannerSemgrep  Scanner = "semgrep"
)

// Scanners lists every optional scanner in report order.
func Scanners() []Scanner {
	return []Scanner{ScannerGitleaks, ScannerOSV, ScannerSemgrep}
}

// ScannerState is what detection found for one scanner.
type ScannerState uint8

// Detection results. creep runs no external scanner yet, so every state
// leaves the scanner's classes not evaluated.
const (
	ScannerNotEnabled ScannerState = iota // not in scanners.enabled
	ScannerMissing                        // enabled, not on PATH
	ScannerRefused                        // the PATH match is in the repository, the current directory or a relative PATH entry
	ScannerFound                          // enabled and on PATH outside the repository
)

// ScannerCheck is one scanner's detection result.
type ScannerCheck struct {
	Scanner Scanner
	State   ScannerState
}

// ScannerEnv is what detection reads: the PATH and PATHEXT values and the
// absolute path of the scanned repository, which scan requires to be the
// current directory.
type ScannerEnv struct {
	Path    string
	PathExt string // Windows only
	Repo    string
}

// DetectScanners reports each optional scanner's state. It looks the exact
// name up on PATH as the OS would and never executes anything. The first
// match decides, so a binary in the repository, the current directory or a
// relative PATH entry is refused rather than skipped for a later one: that
// is the binary a shell would run.
func DetectScanners(enabled []string, env ScannerEnv) []ScannerCheck {
	on := make(map[string]bool, len(enabled))
	for _, name := range enabled {
		on[name] = true
	}
	out := make([]ScannerCheck, 0, len(Scanners()))
	for _, s := range Scanners() {
		state := ScannerNotEnabled
		if on[string(s)] {
			state = lookScanner(string(s), env)
		}
		out = append(out, ScannerCheck{Scanner: s, State: state})
	}
	return out
}

// lookScanner finds the first PATH match of name and classifies it.
func lookScanner(name string, env ScannerEnv) ScannerState {
	for _, dir := range pathDirs(env.Path) {
		for _, file := range candidateNames(name, env.PathExt) {
			bin := filepath.Join(dir, file)
			if !isExecutable(bin) {
				continue
			}
			if !filepath.IsAbs(dir) || insideRepo(bin, env.Repo) {
				return ScannerRefused
			}
			return ScannerFound
		}
	}
	return ScannerMissing
}

// pathDirs lists the directories searched, in order. An empty entry means
// the current directory, and Windows searches the current directory first.
func pathDirs(path string) []string {
	dirs := filepath.SplitList(path)
	for i, d := range dirs {
		if d == "" {
			dirs[i] = "."
		}
	}
	if runtime.GOOS == "windows" {
		dirs = append([]string{"."}, dirs...)
	}
	return dirs
}

// candidateNames is name plus each PATHEXT extension on Windows, or name
// alone elsewhere.
func candidateNames(name, pathExt string) []string {
	if runtime.GOOS != "windows" {
		return []string{name}
	}
	if pathExt == "" {
		pathExt = ".COM;.EXE;.BAT;.CMD"
	}
	var out []string
	for _, ext := range strings.Split(pathExt, ";") {
		if ext != "" {
			out = append(out, name+strings.ToLower(ext))
		}
	}
	return out
}

// isExecutable reports a regular file (after links) that the OS would run:
// any such file on Windows, where PATHEXT decides, one with an execute bit
// elsewhere.
func isExecutable(bin string) bool {
	info, err := os.Stat(bin)
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	return runtime.GOOS == "windows" || info.Mode().Perm()&0o111 != 0
}

// insideRepo reports whether bin, or the file its links resolve to, lies
// in repo. An empty or relative repo fails closed: everything is inside.
func insideRepo(bin, repo string) bool {
	if repo == "" || !filepath.IsAbs(repo) {
		return true
	}
	roots := []string{repo}
	if real, err := filepath.EvalSymlinks(repo); err == nil {
		roots = append(roots, real)
	}
	bins := []string{bin}
	if real, err := filepath.EvalSymlinks(bin); err == nil {
		bins = append(bins, real)
	}
	for _, r := range roots {
		for _, b := range bins {
			if within(b, r) {
				return true
			}
		}
	}
	return false
}

// within reports whether path is root or below it; filepath.Rel compares
// case-insensitively on Windows.
func within(path, root string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}
