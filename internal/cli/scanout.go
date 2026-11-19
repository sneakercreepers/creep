package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"slices"
	"strings"

	"github.com/sneakercreepers/creep/internal/calibrate"
	"github.com/sneakercreepers/creep/internal/exitcode"
	"github.com/sneakercreepers/creep/internal/report"
	"github.com/sneakercreepers/creep/internal/state"
	"github.com/sneakercreepers/creep/internal/static"
)

// reportNames are the files scan writes in .creep, per report.formats.
var reportNames = map[string]string{"json": "report.json", "markdown": "report.md", "sarif": "report.sarif"}

// finish ends the run state, builds and writes the report, prints the
// result and maps it to the exit code.
func (s *session) finish(e env, cal calibrate.Calibration, res scanResult) int {
	done := s.stats.start(phaseReport)
	rep, err := s.buildReport(cal, res)
	if err != nil {
		printError(e.stderr, "creep scan", err)
		return exitcode.ConfigError
	}
	written, err := writeReports(s.cfg.Report.Formats, rep)
	done()
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
	s.printStats(e)
	return exitcode.ForReport(rep.Run.Incomplete, gate)
}

func (s *session) buildReport(cal calibrate.Calibration, res scanResult) (*report.Report, error) {
	reason := incompleteReason(res.stop, res.findings, res.gaps)
	if reason == "" && res.noRoutes {
		reason = reasonNoRoutes
	}
	if reason == "" && res.scanners.failed {
		reason = reasonScannerFailed
	}
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
		Run: s.run.Summary(), ScanIncomplete: res.stop != "",
		Findings: append(slices.Clip(res.findings), res.scanners.findings...),
		Classes: classCoverage(coverageInput{
			cal: cal.Result, findings: res.findings, planned: res.planned,
			gapped: res.stop != "" || fileGapped(res.gaps),
		}),
		NotEvaluated: res.gaps, Scanners: res.scanners.coverage, DataHandling: data,
		NoRoutesIn: noRoutesIn(res.noRoutes),
	})
}

// noRoutesIn names the frameworks static looked in when it found no route.
func noRoutesIn(noRoutes bool) []string {
	if !noRoutes {
		return nil
	}
	return static.FrameworkNames()
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
	printNoRoutes(w, rep.NoRoutesIn)
	printFindings(w, rep.Findings, len(rep.NoRoutesIn) > 0)
	printGaps(w, rep.Coverage.NotEvaluated)
	printClasses(w, rep.Coverage.Classes)
	printScanners(w, rep.Coverage.Scanners)
	if rep.Run.Incomplete {
		fmt.Fprintln(w, incompleteMark(rep))
	}
	if len(written) > 0 {
		fmt.Fprintf(w, "reports: %s\n", strings.Join(written, " "))
	}
	return nil
}

// printStats prints --stats after the result: on stdout with the text
// summary, on stderr when stdout carries a report, so it never corrupts one.
func (s *session) printStats(e env) {
	if !s.opts.stats {
		return
	}
	w := e.stdout
	if s.cfg.Output.Format != "text" {
		w = e.stderr
	}
	s.stats.print(w, pricingFor(s.opts, s.cfg.Model.Contract))
}

// incompleteMark states the reason and how much was not evaluated. With no
// route nothing was, so a count of files and findings would understate it
// (#248).
func incompleteMark(rep *report.Report) string {
	if len(rep.NoRoutesIn) > 0 {
		return fmt.Sprintf("INCOMPLETE RUN (reason %s): static found no route, so no class was evaluated; this is not a clean result", rep.Run.Reason)
	}
	n := len(rep.Coverage.NotEvaluated)
	for _, f := range rep.Findings {
		if f.Status == report.StatusNotEvaluated {
			n++
		}
	}
	return fmt.Sprintf("INCOMPLETE RUN (reason %s): %d not evaluated; this is not a clean result", rep.Run.Reason, n)
}

// printNoRoutes says where static looked when it found no route (#207).
func printNoRoutes(w io.Writer, frameworks []string) {
	if len(frameworks) > 0 {
		fmt.Fprintf(w, "routes: no %s routes found; no class was evaluated\n", strings.Join(frameworks, "/"))
	}
}

// printFindings counts findings by status and lists the probable and
// verified ones; `creep why <id>` shows the rest of the evidence. With no
// route there is no sink to leave undecided, and "0 not evaluated" would
// read as full coverage (#248), so that count gives way to the reason.
func printFindings(w io.Writer, findings []report.Finding, noRoutes bool) {
	counts := map[report.Status]int{}
	for _, f := range findings {
		counts[f.Status]++
	}
	undecided := fmt.Sprintf("%d not evaluated", counts[report.StatusNotEvaluated])
	if noRoutes {
		undecided = "no sink to evaluate"
	}
	fmt.Fprintf(w, "findings: %d verified, %d probable, %d discarded, %s\n",
		counts[report.StatusVerified], counts[report.StatusProbable], counts[report.StatusDiscarded], undecided)
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

// printScanners lists each optional scanner, its status and its classes.
// Names, statuses and classes are IDs report.New checked.
func printScanners(w io.Writer, scanners []report.ScannerCoverage) {
	for _, s := range scanners {
		verb := "not evaluated"
		if s.Status == report.ScannerEvaluated {
			verb = "evaluated"
		}
		fmt.Fprintf(w, "scanner %s: %s; %s: %s\n", s.Name, s.Status, verb, strings.Join(s.Classes, ", "))
	}
}

func location(f report.Finding) string {
	if f.Line > 0 {
		return fmt.Sprintf("%s:%d", f.Path, f.Line)
	}
	return f.Path
}
