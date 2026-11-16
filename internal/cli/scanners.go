package cli

import (
	"os"

	"github.com/sneakercreepers/creep/internal/report"
	"github.com/sneakercreepers/creep/internal/static"
)

// scannerClasses names the report classes an optional scanner would add:
// secrets in the code and its history for gitleaks, known-vulnerable
// dependencies for osv-scanner, and semgrep rule classes the reader does not
// evaluate. An unknown scanner gets none, which report.New refuses.
func scannerClasses(s static.Scanner) []string {
	switch s {
	case static.ScannerGitleaks:
		return []string{"hardcoded_secret"}
	case static.ScannerOSV:
		return []string{"vulnerable_dependency"}
	case static.ScannerSemgrep:
		return []string{"xss", "insecure_deserialization", "weak_crypto"}
	}
	return nil
}

// scannerStatus maps a detection result to the report. A scanner found on
// PATH is still not run: creep executes no external program (ADR 0010).
func scannerStatus(st static.ScannerState) report.ScannerStatus {
	switch st {
	case static.ScannerNotEnabled:
		return report.ScannerNotEnabled
	case static.ScannerMissing:
		return report.ScannerMissing
	case static.ScannerFound:
		return report.ScannerNotRun
	}
	return report.ScannerRefused // static.ScannerRefused, or unknown: the strict side
}

// scannerCoverage detects the enabled scanners and lists every scanner
// with the classes it would cover. Scan runs in the repository, so the
// working directory is the repository; if it cannot be read, detection
// gets no repository and refuses every match.
func scannerCoverage(enabled []string) []report.ScannerCoverage {
	repo, err := os.Getwd()
	if err != nil {
		repo = ""
	}
	checks := static.DetectScanners(enabled, static.ScannerEnv{
		Path: os.Getenv("PATH"), PathExt: os.Getenv("PATHEXT"), Repo: repo,
	})
	out := make([]report.ScannerCoverage, len(checks))
	for i, c := range checks {
		out[i] = report.ScannerCoverage{Name: string(c.Scanner), Status: scannerStatus(c.State), Classes: scannerClasses(c.Scanner)}
	}
	return out
}
