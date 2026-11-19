package repofile

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

// ScannerCheck is one scanner's detection result. Path is the binary's
// final path (links and junctions resolved) when State is ScannerFound:
// the file a runner executes, never the name looked up again.
type ScannerCheck struct {
	Scanner Scanner
	State   ScannerState
	Path    string
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
		check := ScannerCheck{Scanner: s, State: ScannerNotEnabled}
		if on[string(s)] {
			check.State, check.Path = lookScanner(string(s), env)
		}
		out = append(out, check)
	}
	return out
}

// lookScanner finds the first PATH match of name and classifies it; a
// found binary comes with its final path.
func lookScanner(name string, env ScannerEnv) (ScannerState, string) {
	for _, dir := range pathDirs(env.Path) {
		for _, file := range candidateNames(name, env.PathExt) {
			bin := filepath.Join(dir, file)
			if !isExecutable(bin) {
				continue
			}
			if !filepath.IsAbs(dir) {
				return ScannerRefused, ""
			}
			final, ok := OutsideRepo(bin, env.Repo)
			if !ok {
				return ScannerRefused, ""
			}
			return ScannerFound, final
		}
	}
	return ScannerMissing, ""
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
