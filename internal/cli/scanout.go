package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"

	"github.com/sneakercreepers/creep/internal/calibrate"
	"github.com/sneakercreepers/creep/internal/exitcode"
	"github.com/sneakercreepers/creep/internal/report"
	"github.com/sneakercreepers/creep/internal/state"
)

// reportNames are the files scan writes in .creep, per report.formats.
var reportNames = map[string]string{"json": "report.json", "markdown": "report.md", "sarif": "report.sarif"}

// finish ends the run state, builds and writes the report, prints the
// result and maps it to the exit code.
func (s *session) finish(e env, cal calibrate.Calibration, res scanResult) int {
	rep, err := s.buildReport(cal, res)
	if err != nil {
		printError(e.stderr, "creep scan", err)
		return exitcode.ConfigError
	}
	written, err := writeReports(s.cfg.Report.Formats, rep)
	if err != nil {
		printError(e.stderr, "creep scan", err)
		return exitcode.ConfigError
	}
	gate, err := gateExceeded(s.cfg.Gates.PR, rep.Findings)
	if err != nil {
		printError(e.stderr, "creep scan", err)
		return exitcode.ConfigError
	}
	if err := printScan(e, s.cfg.Output.Format, cal, rep, written); err != nil {
		printError(e.stderr, "creep scan", err)
		return exitcode.ConfigError
	}
	return exitcode.ForReport(rep.Run.Incomplete, gate)
}

func (s *session) buildReport(cal calibrate.Calibration, res scanResult) (*report.Report, error) {
	reason := incompleteReason(res.stop, res.findings, res.gaps)
	outcome := state.OutcomeComplete
	if reason != "" {
		outcome = state.OutcomeIncomplete
	}
	if err := s.run.Finish(outcome, reason); err != nil {
		return nil, err
	}
	data, err := dataHandling(s.link.egress)
	if err != nil {
		return nil, err
	}
	return report.New(report.Input{
		Run: s.run.Summary(), ScanIncomplete: res.stop != "", Findings: res.findings,
		Classes: classCoverage(coverageInput{
			cal: cal.Result, findings: res.findings, planned: res.planned,
			gapped: res.stop != "" || fileGapped(res.gaps),
		}),
		NotEvaluated: res.gaps, DataHandling: data,
	})
}

// dataHandling summarizes egress.log; a run with no link writes none.
func dataHandling(egress string) (report.DataHandling, error) {
	if egress == "" {
		return report.DataHandling{}, nil
	}
	f, err := os.Open(egress)
	if err != nil {
		return report.DataHandling{}, fmt.Errorf("data handling: %w", err)
	}
	defer f.Close()
	return report.SummarizeEgress(f)
}

// writeReports writes each configured format into .creep. Each file is
// removed and created anew, never opened through a link a cloned
// repository planted there, and the root keeps every write inside .creep.
func writeReports(formats []string, rep *report.Report) ([]string, error) {
	root, err := os.OpenRoot(stateDir)
	if err != nil {
		return nil, fmt.Errorf("reports: %w", err)
	}
	defer root.Close()
	var written []string
	for _, format := range formats {
		name, ok := reportNames[format]
		if !ok {
			return nil, fmt.Errorf("reports: unknown format %q", format)
		}
		var b bytes.Buffer
		if err := renderReport(&b, format, rep); err != nil {
			return nil, err
		}
		if err := replaceInRoot(root, name, b.Bytes()); err != nil {
			return nil, fmt.Errorf("reports: %w", err)
		}
		written = append(written, path.Join(stateDir, name))
	}
	return written, nil
}

func replaceInRoot(root *os.Root, name string, data []byte) error {
	if err := root.Remove(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func renderReport(w io.Writer, format string, rep *report.Report) error {
	switch format {
	case "json":
		return report.WriteJSON(w, rep)
	case "markdown":
		return report.WriteMarkdown(w, rep)
	case "sarif":
		return report.WriteSARIF(w, rep)
	}
	return fmt.Errorf("unknown report format %q", format)
}

// printScan prints the text summary, or the report itself in another
// output.format (--format). The incomplete mark goes to stdout in text and
// to stderr otherwise, so it is never lost in a redirected report.
func printScan(e env, format string, cal calibrate.Calibration, rep *report.Report, written []string) error {
	if format != "text" {
		if err := renderReport(e.stdout, format, rep); err != nil {
			return err
		}
		if rep.Run.Incomplete {
			fmt.Fprintln(e.stderr, incompleteMark(rep))
		}
		return nil
	}
	w := e.stdout
	fmt.Fprintf(w, "calibration: %s\n", escapeControl(cal.Header()))
	printFindings(w, rep.Findings)
	printGaps(w, rep.Coverage.NotEvaluated)
	printClasses(w, rep.Coverage.Classes)
	if rep.Run.Incomplete {
		fmt.Fprintln(w, incompleteMark(rep))
	}
	if len(written) > 0 {
		fmt.Fprintf(w, "reports: %s\n", strings.Join(written, " "))
	}
	return nil
}

// incompleteMark states the reason and how much was not evaluated.
func incompleteMark(rep *report.Report) string {
	n := len(rep.Coverage.NotEvaluated)
	for _, f := range rep.Findings {
		if f.Status == report.StatusNotEvaluated {
			n++
		}
	}
	return fmt.Sprintf("INCOMPLETE RUN (reason %s): %d not evaluated; this is not a clean result", rep.Run.Reason, n)
}

// printFindings counts findings by status and lists the probable and
// verified ones; `creep why <id>` shows the rest of the evidence.
func printFindings(w io.Writer, findings []report.Finding) {
	counts := map[report.Status]int{}
	for _, f := range findings {
		counts[f.Status]++
	}
	fmt.Fprintf(w, "findings: %d verified, %d probable, %d discarded, %d not evaluated\n",
		counts[report.StatusVerified], counts[report.StatusProbable], counts[report.StatusDiscarded], counts[report.StatusNotEvaluated])
	for _, f := range findings {
		if f.Status == report.StatusVerified || f.Status == report.StatusProbable {
			fmt.Fprintf(w, "  %s  %s  %s  %s\n", f.ID, f.Status, f.Class, escapeControl(location(f)))
		}
	}
}

func printGaps(w io.Writer, gaps []report.NotEvaluated) {
	if len(gaps) == 0 {
		return
	}
	fmt.Fprintf(w, "files not evaluated in full: %d\n", len(gaps))
	for _, g := range gaps {
		fmt.Fprintf(w, "  %s  %s\n", escapeControl(g.Path), g.Reason)
	}
}

func printClasses(w io.Writer, classes []report.ClassCoverage) {
	parts := make([]string, len(classes))
	for i, c := range classes {
		parts[i] = fmt.Sprintf("%s %s", c.Class, c.Status)
	}
	fmt.Fprintf(w, "coverage: %s\n", strings.Join(parts, ", "))
}

func location(f report.Finding) string {
	if f.Line > 0 {
		return fmt.Sprintf("%s:%d", f.Path, f.Line)
	}
	return f.Path
}
