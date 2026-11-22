package report

import "fmt"

// ScannerStatus is whether an optional external scanner evaluated its
// classes. Only evaluated means it did (ADR 0013); failed means it was run
// and evaluated nothing, which the caller reports as an incomplete run.
type ScannerStatus string

// Scanner statuses, a closed set.
const (
	ScannerNotEnabled ScannerStatus = "not_enabled" // not in scanners.enabled
	ScannerMissing    ScannerStatus = "missing"     // enabled, not on PATH
	ScannerRefused    ScannerStatus = "refused"     // its final path is in the repository or the current directory
	ScannerNotRun     ScannerStatus = "not_run"     // installed, but has no offline mode creep can run
	ScannerEvaluated  ScannerStatus = "evaluated"   // ran offline; its findings are in the report
	ScannerFailed     ScannerStatus = "failed"      // ran but evaluated nothing (exit status, timeout, bad output)
)

var scannerStatuses = map[ScannerStatus]bool{
	ScannerNotEnabled: true, ScannerMissing: true, ScannerRefused: true, ScannerNotRun: true,
	ScannerEvaluated: true, ScannerFailed: true,
}

// ScannerCoverage is one optional external scanner and the classes it
// covers; unless Status is evaluated, this run did not evaluate them
// through it.
type ScannerCoverage struct {
	Name    string        `json:"name"`
	Status  ScannerStatus `json:"status"`
	Classes []string      `json:"classes"`
	// RepoIgnoreSkipped: the repository held a suppression file the scanner
	// always reads (gitleaks' .gitleaksignore) and the run did not apply it
	// (#226). Not in the frozen JSON v1 schema; the text summary, Markdown
	// and SARIF say it.
	RepoIgnoreSkipped bool `json:"-"`
}

// SkipNote is what the readable formats add when RepoIgnoreSkipped is set,
// or "".
func (s ScannerCoverage) SkipNote() string {
	if !s.RepoIgnoreSkipped {
		return ""
	}
	return "the repository's suppression file was not applied, so it hid no finding"
}

func checkScanners(in []ScannerCoverage) ([]ScannerCoverage, error) {
	if len(in) == 0 {
		return nil, nil
	}
	out := make([]ScannerCoverage, len(in))
	seen := make(map[string]bool, len(in))
	for i, s := range in {
		if err := checkScanner(s, seen); err != nil {
			return nil, err
		}
		s.Classes = append([]string(nil), s.Classes...)
		out[i] = s
	}
	return out, nil
}

func checkScanner(s ScannerCoverage, seen map[string]bool) error {
	switch {
	case !idPattern.MatchString(s.Name):
		return fmt.Errorf("%w: scanner %q", ErrInvalid, s.Name)
	case seen[s.Name]:
		return fmt.Errorf("%w: duplicate scanner %q", ErrInvalid, s.Name)
	case !scannerStatuses[s.Status]:
		return fmt.Errorf("%w: scanner %s: status %q", ErrInvalid, s.Name, s.Status)
	case len(s.Classes) == 0:
		return fmt.Errorf("%w: scanner %s: no classes", ErrInvalid, s.Name)
	}
	for _, c := range s.Classes {
		if !idPattern.MatchString(c) {
			return fmt.Errorf("%w: scanner %s: class %q", ErrInvalid, s.Name, c)
		}
	}
	seen[s.Name] = true
	return nil
}
