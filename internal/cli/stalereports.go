package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"slices"
)

// removeReports deletes every report file in .creep once the state store
// has checked the directory, before the run does anything else. A report the
// scanned repository committed there, or one an earlier run wrote in a
// format report.formats no longer lists, would otherwise sit next to this
// run's output, and a pipeline that uploads .creep/report.sarif would publish
// it (pentest P5). Remove does not follow a final link, so a planted link is
// removed and its target left alone; a planted non-empty directory cannot be
// removed and stops the scan.
func removeReports() error {
	root, err := os.OpenRoot(stateDir)
	if err != nil {
		return fmt.Errorf("reports: %w", err)
	}
	defer root.Close()
	for _, name := range slices.Sorted(maps.Values(reportNames)) {
		if err := root.Remove(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("reports: remove stale %s: %w", name, err)
		}
	}
	return nil
}
