package report

import "fmt"

// ScannerStatus is why an optional external scanner did not evaluate its
// classes. creep runs none yet (ADR 0010), so every status means not
// evaluated; none makes the run incomplete.
type ScannerStatus string

// Scanner statuses, a closed set.
const (
	ScannerNotEnabled ScannerStatus = "not_enabled" // not in scanners.enabled
	ScannerMissing    ScannerStatus = "missing"     // enabled, not on PATH
	ScannerRefused    ScannerStatus = "refused"     // the PATH match is in the repository or the current directory
	ScannerNotRun     ScannerStatus = "not_run"     // installed, but this version does not run it
)

var scannerStatuses = map[ScannerStatus]bool{
	ScannerNotEnabled: true, ScannerMissing: true, ScannerRefused: true, ScannerNotRun: true,
}

// ScannerCoverage is one optional external scanner and the classes it
// would cover, which this run did not evaluate through it.
type ScannerCoverage struct {
	Name    string        `json:"name"`
	Status  ScannerStatus `json:"status"`
	Classes []string      `json:"classes"`
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
