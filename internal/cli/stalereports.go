package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"slices"
)

// removeReports deletes every report file and reproduction bundle in
// .creep once the state store
// has checked the directory, before the run does anything else. A report the
// scanned repository committed there, or one an earlier run wrote in a
// format report.formats no longer lists, would otherwise sit next to this
// run's output, and a pipeline that uploads .creep/report.sarif would publish
// it (pentest P5). Remove does not follow a final link, so a planted link is
// removed and its target left alone. A name it cannot remove, such as a
// planted non-empty directory, is returned and the run goes on, so the scan
// still prints its result and then fails its exit code (#209). root is the
// store's own handle, never .creep reopened by path.
func removeReports(root *os.Root) []error {
	var errs []error
	for _, name := range slices.Sorted(maps.Values(reportNames)) {
		if err := root.Remove(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, fmt.Errorf("remove stale %s: %w", name, err))
		}
	}
	if err := removeBundles(root); err != nil {
		errs = append(errs, err)
	}
	return errs
}
