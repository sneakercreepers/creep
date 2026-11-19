package cli

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/sneakercreepers/creep/internal/report"
	"github.com/sneakercreepers/creep/internal/scanrun"
	"github.com/sneakercreepers/creep/internal/repofile"
)

// reasonScannerFailed marks a run incomplete because an enabled scanner
// ran and evaluated nothing (ADR 0013).
const reasonScannerFailed = "scanner_failed"

// osvDBEnv names the user's offline osv-scanner database; without it
// osv-scanner is not run, since it would go online.
const osvDBEnv = "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY"

// scannerClasses names the report classes an optional scanner covers:
// secrets in the code for gitleaks, known-vulnerable dependencies for
// osv-scanner, and semgrep rule classes the reader does not evaluate. An
// unknown scanner gets none, which report.New refuses.
func scannerClasses(s repofile.Scanner) []string {
	switch s {
	case repofile.ScannerGitleaks:
		return []string{"hardcoded_secret"}
	case repofile.ScannerOSV:
		return []string{"vulnerable_dependency"}
	case repofile.ScannerSemgrep:
		return []string{"xss", "insecure_deserialization", "weak_crypto"}
	}
	return nil
}

// scannerStatus maps a detection result to the report. A found scanner
// is not_run until the runner says otherwise.
func scannerStatus(st repofile.ScannerState) report.ScannerStatus {
	switch st {
	case repofile.ScannerNotEnabled:
		return report.ScannerNotEnabled
	case repofile.ScannerMissing:
		return report.ScannerMissing
	case repofile.ScannerFound:
		return report.ScannerNotRun
	}
	return report.ScannerRefused // repofile.ScannerRefused, or unknown: the strict side
}

// runStatus maps a run outcome to the report; an unknown one is failed,
// which makes the run incomplete.
func runStatus(o scanrun.Outcome) report.ScannerStatus {
	switch o {
	case scanrun.NotRun:
		return report.ScannerNotRun
	case scanrun.Refused:
		return report.ScannerRefused
	case scanrun.Evaluated:
		return report.ScannerEvaluated
	}
	return report.ScannerFailed
}

// scannerRun is what the optional scanners added to a scan.
type scannerRun struct {
	coverage []report.ScannerCoverage
	findings []report.Finding
	failed   bool // an enabled scanner ran and evaluated nothing
}

// runScanners detects the enabled scanners, runs each found one through
// run and lists every scanner with its classes. Scan runs in the
// repository, so the working directory is the repository; if it cannot be
// read, detection gets no repository and refuses every match.
func runScanners(ctx context.Context, enabled []string, run func(context.Context, scanrun.Job) scanrun.Result, stderr io.Writer) scannerRun {
	repo, err := os.Getwd()
	if err != nil {
		repo = ""
	}
	checks := repofile.DetectScanners(enabled, repofile.ScannerEnv{
		Path: os.Getenv("PATH"), PathExt: os.Getenv("PATHEXT"), Repo: repo,
	})
	var out scannerRun
	for _, c := range checks {
		status := scannerStatus(c.State)
		if c.State == repofile.ScannerFound {
			job := scanrun.Job{Scanner: c.Scanner, Bin: c.Path, Repo: repo, OSVDB: os.Getenv(osvDBEnv), Limits: scanrun.DefaultLimits()}
			res := run(ctx, job)
			status = runStatus(res.Outcome)
			out.findings = append(out.findings, scannerFindings(c.Scanner, res.Findings)...)
			if status == report.ScannerFailed {
				out.failed = true
				fmt.Fprintf(stderr, "creep scan: scanner %s failed: %s; its classes were not evaluated\n", c.Scanner, res.Failure)
			}
		}
		out.coverage = append(out.coverage, report.ScannerCoverage{Name: string(c.Scanner), Status: status, Classes: scannerClasses(c.Scanner)})
	}
	return out
}

// scannerFindings turns runner findings into probable report findings of
// the scanner's class. IDs are the scanner's prefix and the runner's hex
// key; the path was checked to lie inside the repository.
func scannerFindings(s repofile.Scanner, in []scanrun.Finding) []report.Finding {
	class, prefix := scannerFindingClass(s)
	out := make([]report.Finding, 0, len(in))
	for _, f := range in {
		out = append(out, report.Finding{ID: prefix + "-" + f.Key, Class: class, Status: report.StatusProbable, Path: f.Path, Line: f.Line})
	}
	return out
}

// scannerFindingClass is the class and ID prefix of a scanner's findings;
// only scanners the runner can run have one.
func scannerFindingClass(s repofile.Scanner) (class, prefix string) {
	switch s {
	case repofile.ScannerGitleaks:
		return "hardcoded_secret", "gitleaks"
	case repofile.ScannerOSV:
		return "vulnerable_dependency", "osv"
	}
	return "unknown", "unknown" // never produced: the runner runs only the two above
}
