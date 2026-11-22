package cli

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"github.com/sneakercreepers/creep/internal/exitcode"
	"github.com/sneakercreepers/creep/internal/report"
	"github.com/sneakercreepers/creep/internal/state"
)

// maxWhyReportBytes caps the report why reads; scan writes far less.
const maxWhyReportBytes = 64 << 20

// runWhy prints the evidence behind one finding of the last scan's JSON
// report. The ID is checked against the report's ID pattern before any
// file is read, and every repository string is escaped.
func runWhy(e env, args []string) int {
	if len(args) != 1 {
		printError(e.stderr, "creep why", fmt.Errorf("want exactly one finding ID, got %d arguments", len(args)))
		return exitcode.ConfigError
	}
	id := args[0]
	if !report.ValidID(id) {
		printError(e.stderr, "creep why", fmt.Errorf("invalid finding ID %q", id))
		return exitcode.ConfigError
	}
	rep, err := readLastReport()
	if err != nil {
		printError(e.stderr, "creep why", err)
		return exitcode.ConfigError
	}
	f, ok := rep.Finding(id)
	if !ok {
		printError(e.stderr, "creep why", fmt.Errorf("no finding %s in %s", id, path.Join(stateDir, reportNames["json"])))
		return exitcode.ConfigError
	}
	printWhy(e.stdout, f)
	return exitcode.OK
}

// readLastReport reads .creep/report.json without creating .creep, and
// through report.ReadJSON, which refuses anything scan would not write.
func readLastReport() (*report.Report, error) {
	name := reportNames["json"]
	root, err := openStateDir()
	if err != nil {
		return nil, err
	}
	defer root.Close()
	data, err := readInRoot(root, name, maxWhyReportBytes)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path.Join(stateDir, name), err)
	}
	return report.ReadJSON(bytes.NewReader(data))
}

// openStateDir opens .creep for reading without creating it, through the
// state store's own checks, so a .creep link, junction or file a cloned
// repository planted is never read as the last scan (#209).
func openStateDir() (*os.Root, error) {
	if _, err := os.Lstat(stateDir); err != nil {
		return nil, fmt.Errorf("no scan report in this directory (run creep scan with json in report.formats): %w", err)
	}
	return state.OpenExisting(stateDir)
}

func printWhy(w io.Writer, f report.Finding) {
	fmt.Fprintf(w, "finding %s\n", f.ID)
	fmt.Fprintf(w, "  status:     %s\n", f.Status)
	fmt.Fprintf(w, "  class:      %s\n", f.Class)
	fmt.Fprintf(w, "  location:   %s\n", escapeControl(location(f)))
	if f.Reason != "" {
		fmt.Fprintf(w, "  reason:     %s\n", f.Reason)
	}
	if f.Status == report.StatusNotEvaluated && f.Reason != reasonInconclusive {
		fmt.Fprintln(w, "  evidence:   none; this sink was not evaluated")
		return
	}
	fmt.Fprintf(w, "  confidence: %d/100\n", f.Confidence)
	fmt.Fprintf(w, "  evidence:   %s\n", evidenceText(f.Evidence))
	if f.Partial {
		fmt.Fprintln(w, "  slice:      partial; lines were left out, so this verdict is partial coverage")
	}
	if label := f.Stability.Text(); label != "" {
		fmt.Fprintf(w, "  stability:  %s\n", label)
	}
}

func evidenceText(ranges []report.LineRange) string {
	if len(ranges) == 0 {
		return "no lines cited"
	}
	parts := make([]string, len(ranges))
	for i, r := range ranges {
		parts[i] = fmt.Sprintf("%d-%d", r.Start, r.End)
		if r.Start == r.End {
			parts[i] = fmt.Sprint(r.Start)
		}
	}
	return "lines " + strings.Join(parts, ", ")
}
