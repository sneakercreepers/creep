package cli

import (
	"github.com/sneakercreepers/creep/internal/calibrate"
	"github.com/sneakercreepers/creep/internal/config"
	"github.com/sneakercreepers/creep/internal/report"
	"github.com/sneakercreepers/creep/internal/static"
)

// classTemplateInjection is a reader class calibration does not measure yet.
const classTemplateInjection = "template_injection"

// kindClass names the report class of a static sink kind, using the
// calibration's names so findings and coverage rows agree. An unmapped kind
// keeps static's own name; its sinks are never planned.
func kindClass(k static.SinkKind) string {
	switch k {
	case static.SinkSQL:
		return string(calibrate.ClassSQLi)
	case static.SinkShell:
		return string(calibrate.ClassCommandInjection)
	case static.SinkFile:
		return string(calibrate.ClassPathTraversal)
	case static.SinkHTTPClient:
		return string(calibrate.ClassSSRF)
	case static.SinkTemplate:
		return classTemplateInjection
	case static.SinkNoSQL:
		return string(calibrate.ClassNoSQLInjection)
	}
	return k.String()
}

// readClasses are the classes the pipeline can evaluate: one per sink kind.
var readClasses = map[string]bool{
	string(calibrate.ClassSQLi): true, string(calibrate.ClassCommandInjection): true,
	string(calibrate.ClassPathTraversal): true, string(calibrate.ClassSSRF): true,
	classTemplateInjection: true, string(calibrate.ClassNoSQLInjection): true,
}

// classSeverity rates a confirmed finding of each class for the gate
// (ADR 0009). A class missing here is rated critical: the strict side.
var classSeverity = map[string]string{
	string(calibrate.ClassSQLi):             "critical",
	string(calibrate.ClassCommandInjection): "critical",
	string(calibrate.ClassPathTraversal):    "high",
	string(calibrate.ClassSSRF):             "high",
	classTemplateInjection:                  "high",
	string(calibrate.ClassNoSQLInjection):   "critical",
	// Optional scanner classes (ADR 0013): probable until a person checks.
	"hardcoded_secret":      "high",
	"vulnerable_dependency": "high",
}

// coverageInput is what decides each class's coverage.
type coverageInput struct {
	cal      calibrate.Result
	findings []report.Finding
	gapped   bool // a file gap or an early stop: no class can be covered
	planned  bool // false when the planner refused the input or there was no route to plan
}

// classCoverage lists every calibrated class, then template injection.
// A class the pipeline cannot evaluate is not evaluated; a readable one is
// partial when anything that could hold it was not evaluated in full.
func classCoverage(in coverageInput) []report.ClassCoverage {
	names := make([]string, 0, len(calibrate.Classes())+1)
	for _, c := range calibrate.Classes() {
		names = append(names, string(c))
	}
	names = append(names, classTemplateInjection)
	out := make([]report.ClassCoverage, len(names))
	for i, name := range names {
		out[i] = report.ClassCoverage{Class: name, Status: classStatus(name, in)}
		for _, s := range in.cal.Classes {
			if string(s.Class) == name {
				out[i].Detected, out[i].Tasks = s.Correct, s.Total
			}
		}
	}
	return out
}

func classStatus(name string, in coverageInput) report.ClassStatus {
	switch {
	case !readClasses[name] || !in.planned:
		return report.ClassNotEvaluated
	case in.gapped:
		return report.ClassPartial
	}
	for _, f := range in.findings {
		if f.Class == name && findingGap(f) != "" {
			return report.ClassPartial
		}
	}
	return report.ClassCovered
}

// findingGap is why a finding leaves its class partial, or "". Only the
// tier's low-risk skip is by design; everything else is a gap.
func findingGap(f report.Finding) string {
	switch {
	case f.Status == report.StatusNotEvaluated && f.Reason == reasonLowRisk:
		return ""
	case f.Status == report.StatusNotEvaluated && f.Reason == "":
		return reasonNotEvaluated
	case f.Status == report.StatusNotEvaluated:
		return f.Reason
	case f.Partial:
		return reasonPartialSlice
	}
	return ""
}

// incompleteReason is why the run is not complete, or "" when it is: an
// early stop first, then the first finding gap in sink order, then the
// first file gap. Files left out with evidence (a vendor tree with its
// package manager's mark, route-free generated or minified files) do not
// count (report.SkipReason.ByDesign).
func incompleteReason(stop string, findings []report.Finding, gaps []report.NotEvaluated) string {
	if stop != "" {
		return stop
	}
	for _, f := range findings {
		if gap := findingGap(f); gap != "" {
			return gap
		}
	}
	for _, g := range gaps {
		if !g.Reason.ByDesign() {
			return string(g.Reason)
		}
	}
	return ""
}

// fileGapped reports a file gap that makes every class partial.
func fileGapped(gaps []report.NotEvaluated) bool {
	for _, g := range gaps {
		if !g.Reason.ByDesign() {
			return true
		}
	}
	return false
}

// gateExceeded reports whether a finding trips gate (gates.pr).
func gateExceeded(gate string, findings []report.Finding) (bool, error) {
	for _, f := range findings {
		severity, ok := classSeverity[f.Class]
		if !ok {
			severity = "critical"
		}
		trips, err := config.GateTrips(gate, string(f.Status), severity)
		if err != nil || trips {
			return trips, err
		}
	}
	return false, nil
}
