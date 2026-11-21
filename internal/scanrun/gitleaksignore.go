package scanrun

import (
	"context"
	"os"
	"path/filepath"
)

// gitleaksIgnoreName is the suppression file gitleaks loads from the root
// of every source it scans, whatever its flags say.
const gitleaksIgnoreName = ".gitleaksignore"

// maxGitleaksSources bounds how many gitleaks runs one scan may start when
// the repository root holds a .gitleaksignore, so a root with thousands of
// entries cannot turn one scanner into thousands of processes.
const maxGitleaksSources = 256

// gitleaksPlan scans the repository root in one run, unless the root holds
// a .gitleaksignore (of any type, or one creep cannot rule out). The
// repository is untrusted, so that file must not hide findings (#226):
// gitleaks then runs once per other root entry, each a source whose root
// holds no such file, and the plan records that the file was skipped. A
// root directory with its own .gitleaksignore, or more than
// maxGitleaksSources entries, leaves no clean way to scan: gitleaks is not
// started and the run is incomplete (FailRepoIgnore).
func gitleaksPlan(_ context.Context, job Job) (runPlan, Failure) {
	ignore, err := os.Lstat(filepath.Join(job.Repo, gitleaksIgnoreName))
	if os.IsNotExist(err) {
		return runPlan{sources: []string{job.Repo}}, FailNone
	}
	if err != nil {
		return runPlan{}, FailRepoIgnore
	}
	entries, err := os.ReadDir(job.Repo)
	if err != nil || len(entries) > maxGitleaksSources {
		return runPlan{}, FailRepoIgnore
	}
	plan := runPlan{skippedIgnore: true}
	for _, e := range entries {
		source, ok := gitleaksSource(filepath.Join(job.Repo, e.Name()), ignore)
		if !ok {
			return runPlan{}, FailRepoIgnore
		}
		if source != "" {
			plan.sources = append(plan.sources, source)
		}
	}
	return plan, FailNone
}

// gitleaksSource decides one root entry: "" leaves it out (the ignore file
// itself, compared by identity so a case variant on a case-insensitive
// file system is caught; a link or special file, which a single run would
// not follow either; the .git directory, which gitleaks skips); ok is
// false when the entry is a directory that holds a .gitleaksignore of its
// own.
func gitleaksSource(path string, ignore os.FileInfo) (string, bool) {
	info, err := os.Lstat(path)
	switch {
	case err != nil:
		return "", false
	case os.SameFile(info, ignore):
		return "", true
	case info.Mode().IsRegular():
		return path, true
	case !info.IsDir(), info.Name() == ".git":
		return "", true
	}
	if _, err := os.Lstat(filepath.Join(path, gitleaksIgnoreName)); !os.IsNotExist(err) {
		return "", false
	}
	return path, true
}
