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
)

// reportNames are the files scan writes in .creep, per report.formats.
var reportNames = map[string]string{"json": "report.json", "markdown": "report.md", "sarif": "report.sarif"}

// finish ends the run state, builds and writes the report, prints the
// result and maps it to the exit code.
func (s *session) finish(e env, cal calibrate.Calibration, res scanResult) int {
	done := s.stats.start(phaseReport)
	rep, err := s.buildReport(cal, res)
	if err != nil {
		return s.fail(e, "creep scan", err, exitcode.ConfigError)
	}
	written, unwritten := writeReports(s.store.Root(), s.cfg.Report.Formats, rep)
	done()
	gate, err := s.gate.exceeded(e.stderr, res.verify, rep.Findings)
	if err != nil {
		return s.fail(e, "creep scan", err, exitcode.ConfigError)
	}
	if err := printScan(e, s.cfg.Output.Format, cal, rep, written); err != nil {
		return s.fail(e, "creep scan", err, exitcode.ConfigError)
	}
	if err := s.baseline.save(e.stderr, rep); err != nil {
		unwritten = append(unwritten, err)
	}
	s.printStats(e)
	return reportCode(e, exitcode.ForReport(rep.Run.Incomplete, gate), append(s.staleReports, unwritten...))
}

// reportCode names on stderr, after the result, each report file the run
// could not remove or write, and keeps the run's exit code, never 0 for a
// lost report: a clean run whose report is missing exits 2 (#209).
func reportCode(e env, code int, failed []error) int {
	for _, err := range failed {
		printError(e.stderr, "creep scan: reports", err)
	}
	if len(failed) > 0 && code == exitcode.OK {
		return exitcode.ConfigError
	}
	return code
}

func (s *session) buildReport(cal calibrate.Calibration, res scanResult) (*report.Report, error) {
	reason := incompleteReason(res.stop, res.findings, res.gaps)
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
	fingerprint(res.findings, res.slices)
	findings := append(slices.Clip(res.findings), res.scanners.findings...)
	return report.New(report.Input{
		Run: s.run.Summary(), ScanIncomplete: res.stop != "", Baseline: s.baseline.apply(findings),
		Findings: findings,
		Classes: classCoverage(coverageInput{
			cal: cal.Result, findings: res.findings, planned: res.planned,
			gapped: res.stop != "" || fileGapped(res.gaps),
		}),
		NotEvaluated: res.gaps, Scanners: res.scanners.coverage, DataHandling: data,
		Discovery: res.disc, Verification: res.verify, Incremental: s.incremental,
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

// writeReports writes each configured format into .creep through root, the
// state store's checked handle. Each file is removed and created anew, never
// opened through a link a cloned repository planted there, and the root
// keeps every write inside .creep. A format that cannot be written is
// skipped and returned, so the others and the result are not lost (#209).
func writeReports(root *os.Root, formats []string, rep *report.Report) (written []string, failed []error) {
	for _, format := range formats {
		name, err := writeReport(root, format, rep)
		if err != nil {
			failed = append(failed, err)
			continue
		}
		written = append(written, path.Join(stateDir, name))
	}
	return written, failed
}

func writeReport(root *os.Root, format string, rep *report.Report) (string, error) {
	name, ok := reportNames[format]
	if !ok {
		return "", fmt.Errorf("unknown format %q", format)
	}
	var b bytes.Buffer
	if err := renderReport(&b, format, rep); err != nil {
		return "", fmt.Errorf("%s not written: %w", name, err)
	}
	if err := replaceInRoot(root, name, b.Bytes()); err != nil {
		return "", fmt.Errorf("%s not written: %w", name, err)
	}
	return name, nil
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
		printVerification(e.stderr, rep.Verification)
		printIncremental(e.stderr, rep)
		printBaseline(e.stderr, rep)
		if rep.Run.Incomplete {
			fmt.Fprintln(e.stderr, incompleteMark(rep))
		}
		return nil
	}
	printScanText(e.stdout, cal, rep, written)
	return nil
}

// printScanText is the text summary: every section, then the incomplete
// mark and the report files written.
func printScanText(w io.Writer, cal calibrate.Calibration, rep *report.Report, written []string) {
	fmt.Fprintf(w, "calibration: %s\n", escapeControl(cal.Header()))
	printDiscovery(w, rep.Discovery)
	printFindings(w, rep.Findings)
	printGaps(w, rep.Coverage.NotEvaluated)
	printClasses(w, rep.Coverage.Classes)
	// Beside coverage, so a covered class line never reads as covering them (#365).
	fmt.Fprintf(w, "not looked for in any language: %s\n", report.NotLookedForText())
	if summary := report.ByDesignSummary(rep.Coverage.NotEvaluated); summary != "" {
		// Beside the class line, so "covered" never reads as covering them (#213).
		fmt.Fprintf(w, "coverage excludes %s, listed above\n", summary)
	}
	printIncremental(w, rep)
	printScanners(w, rep.Coverage.Scanners)
	printVerification(w, rep.Verification)
	printBaseline(w, rep)
	if rep.Run.Incomplete {
		fmt.Fprintln(w, incompleteMark(rep))
	}
	if len(written) > 0 {
		fmt.Fprintf(w, "reports: %s\n", strings.Join(written, " "))
	}
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

// fail ends a run that stopped before its result: the error, the stale
// reports it could not remove (still on disk, so a pipeline must not take
// them for this run's), then, with --stats, what the run spent until then,
// all on stderr. A run that fails after spending tokens is when the cost
// matters most (#222).
func (s *session) fail(e env, prefix string, err error, code int) int {
	printError(e.stderr, prefix, err)
	code = reportCode(e, code, s.staleReports)
	if s.opts.stats {
		s.stats.print(e.stderr, pricingFor(s.opts, s.cfg.Model.Contract))
	}
	return code
}

// incompleteMark states the reason and counts the gaps (files and sinks not
// evaluated, verdicts from partial slices) apart from what was left out by
// design (vendor, generated and minified files, tier S's low-risk skips),
// which never makes a run incomplete (#209).
func incompleteMark(rep *report.Report) string {
	gaps, byDesign := 0, 0
	for _, g := range rep.Coverage.NotEvaluated {
		if g.Reason.ByDesign() {
			byDesign++
		} else {
			gaps++
		}
	}
	for _, f := range rep.Findings {
		switch {
		case findingGap(f) != "":
			gaps++
		case f.Status == report.StatusNotEvaluated:
			byDesign++
		}
	}
	return fmt.Sprintf("INCOMPLETE RUN (reason %s): %d not evaluated or partial, %d left out by design; this is not a clean result",
		rep.Run.Reason, gaps, byDesign)
}

// printDiscovery prints the inventory, discovery's whole-file egress and
// the cause of each failed batch. Every value is a count or an ID
// report.New checked.
func printDiscovery(w io.Writer, d report.Discovery) {
	if len(d.Inventory) > 0 {
		parts := make([]string, len(d.Inventory))
		for i, c := range d.Inventory {
			parts[i] = fmt.Sprintf("%s %s %d", c.Kind, c.ID, c.Files)
		}
		fmt.Fprintf(w, "inventory: %s\n", strings.Join(parts, ", "))
	}
	fmt.Fprintf(w, "discovery: %d whole source files sent, redacted\n", d.WholeFiles)
	for _, b := range d.Batches {
		fmt.Fprintf(w, "  %s\n", b.Text())
	}
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
		if f.Status != report.StatusVerified && f.Status != report.StatusProbable {
			continue
		}
		notes := ""
		if f.Partial {
			// A verdict from a cut slice covers only part of the flow (#209).
			notes = "  partial slice"
		}
		if rate := f.PoC.Text(); rate != "" {
			notes += "  " + rate
		}
		if label := f.Stability.Text(); label != "" {
			notes += "  " + label
		}
		notes += suppressionNote(f)
		fmt.Fprintf(w, "  %s  %s  %s  %s%s\n", f.ID, f.Status, f.Class, escapeControl(location(f)), notes)
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
		line := fmt.Sprintf("scanner %s: %s; %s: %s", s.Name, s.Status, verb, strings.Join(s.Classes, ", "))
		if note := s.SkipNote(); note != "" {
			line += "; " + note
		}
		fmt.Fprintln(w, line)
	}
}

// printVerification states the sandbox's outcome; nothing when it is off.
// Every value is an ID report.New checked.
func printVerification(w io.Writer, v report.Verification) {
	if text := v.Text(); text != "" {
		fmt.Fprintf(w, "sandbox: %s\n", text)
	}
}

func location(f report.Finding) string {
	if f.Line > 0 {
		return fmt.Sprintf("%s:%d", f.Path, f.Line)
	}
	return f.Path
}
