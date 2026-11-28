package report

import (
	"fmt"
	"io"
	"sort"
	"strings"
)

const (
	sarifVersion = "2.1.0"
	sarifSchema  = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
	toolURI      = "https://github.com/sneakercreepers/creep"
	srcRoot      = "%SRCROOT%"
)

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool        sarifTool         `json:"tool"`
	Invocations []sarifInvocation `json:"invocations"`
	Results     []sarifResult     `json:"results"`
	Properties  sarifRunProps     `json:"properties"`
}

type sarifRunProps struct {
	SchemaVersion int          `json:"creep_schema_version"`
	Incomplete    bool         `json:"incomplete"`
	Coverage      Coverage     `json:"coverage"`
	DataHandling  DataHandling `json:"data_handling"`
	// The run was scanned past the fitness floor (ADR 0036).
	UnreliableModel bool `json:"unreliable_model,omitempty"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string          `json:"id"`
	ShortDescription sarifMessage    `json:"shortDescription"`
	Properties       *sarifRuleProps `json:"properties,omitempty"`
}

// sarifRuleProps carries the class's CWE as a tag in GitHub code scanning's
// form (external/cwe/cwe-<n>).
type sarifRuleProps struct {
	Tags []string `json:"tags"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifInvocation struct {
	ExecutionSuccessful bool                `json:"executionSuccessful"`
	Notifications       []sarifNotification `json:"toolExecutionNotifications"`
}

type sarifNotification struct {
	Descriptor sarifDescriptor `json:"descriptor"`
	Level      string          `json:"level"`
	Message    sarifMessage    `json:"message"`
	Locations  []sarifLocation `json:"locations,omitempty"`
}

type sarifDescriptor struct {
	ID string `json:"id"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	RuleIndex int             `json:"ruleIndex"`
	Kind      string          `json:"kind"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations"`
	// The baseline (#27): creep's fingerprint, and the entry that keeps
	// the result from the gate.
	PartialFingerprints map[string]string  `json:"partialFingerprints,omitempty"`
	Suppressions        []sarifSuppression `json:"suppressions,omitempty"`
	Properties          sarifResultProp    `json:"properties"`
}

type sarifResultProp struct {
	ID     string `json:"creep_id"`
	Status Status `json:"status"`
	// The PoC's rate (#25), only on a finding a PoC verified.
	PoCVerified int `json:"poc_verified_runs,omitempty"`
	PoCRuns     int `json:"poc_runs,omitempty"`
	// The stability run's counts (#37, ADR 0024), only with --stability.
	Stability *Stability `json:"stability,omitempty"`
	// Set when the model failed the fitness floor (#363, ADR 0036).
	UnreliableModel bool `json:"unreliable_model,omitempty"`
}

type sarifLocation struct {
	Physical sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	Artifact sarifArtifact `json:"artifactLocation"`
	Region   *sarifRegion  `json:"region,omitempty"`
}

type sarifArtifact struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

// WriteSARIF writes r as a SARIF 2.1.0 log for GitHub code scanning. Only
// verified and probable findings become results; an incomplete run has
// executionSuccessful false and an error notification, and every
// not-evaluated file is a warning notification with its reason, after a
// note counting the files no class covers by design (#213).
func WriteSARIF(w io.Writer, r *Report) error {
	rules, index := sarifRules(r.Findings)
	run := sarifRun{
		Tool:        sarifTool{Driver: sarifDriver{Name: r.Tool.Name, Version: r.Tool.Version, InformationURI: toolURI, Rules: rules}},
		Invocations: []sarifInvocation{sarifInvocationOf(r)},
		Results:     sarifResults(r.Findings, index),
		Properties:  sarifRunProps{SchemaVersion: r.SchemaVersion, Incomplete: r.Run.Incomplete, Coverage: r.Coverage, DataHandling: r.DataHandling, UnreliableModel: r.Run.UnreliableModel},
	}
	if err := writeInertJSON(w, sarifLog{Schema: sarifSchema, Version: sarifVersion, Runs: []sarifRun{run}}); err != nil {
		return fmt.Errorf("write SARIF report: %w", err)
	}
	return nil
}

// sarifRules lists one rule per class that has a result, sorted, and maps
// each class to its index.
func sarifRules(findings []Finding) ([]sarifRule, map[string]int) {
	var classes []string
	seen := map[string]bool{}
	for _, f := range findings {
		if sarifLevel(f.Status) != "" && !seen[f.Class] {
			seen[f.Class] = true
			classes = append(classes, f.Class)
		}
	}
	sort.Strings(classes)
	rules := make([]sarifRule, len(classes))
	index := make(map[string]int, len(classes))
	for i, c := range classes {
		rules[i] = sarifRule{ID: c, ShortDescription: sarifMessage{Text: "creep vulnerability class " + c}, Properties: cweTags(c)}
		index[c] = i
	}
	return rules, index
}

// cweTags is the rule's CWE tag, or nil for a class with no known CWE.
func cweTags(class string) *sarifRuleProps {
	cwe := ClassCWE(class)
	if cwe == "" {
		return nil
	}
	return &sarifRuleProps{Tags: []string{"security", "external/cwe/" + strings.ToLower(cwe)}}
}

func sarifResults(findings []Finding, index map[string]int) []sarifResult {
	results := []sarifResult{}
	for _, f := range findings {
		level := sarifLevel(f.Status)
		if level == "" {
			continue
		}
		results = append(results, sarifResult{
			RuleID: f.Class, RuleIndex: index[f.Class], Kind: "fail", Level: level,
			Message:             sarifMessage{Text: resultText(f)},
			Locations:           []sarifLocation{fileLocation(f.Path, f.Line)},
			PartialFingerprints: sarifFingerprints(f), Suppressions: sarifSuppressions(f.Suppression),
			Properties: resultProps(f),
		})
	}
	return results
}

// resultProps are a result's creep properties: its ID and status, the
// PoC's rate and the stability run's counts.
func resultProps(f Finding) sarifResultProp {
	return sarifResultProp{ID: f.ID, Status: f.Status, PoCVerified: f.PoC.Verified, PoCRuns: f.PoC.Runs, Stability: f.Stability, UnreliableModel: f.UnreliableModel}
}

// resultText is a result's message: class, ID and status, the PoC's rate
// when one verified the finding, and the stability run's label.
func resultText(f Finding) string {
	notes := []string{string(f.Status)}
	if rate := f.PoC.Text(); rate != "" {
		notes = append(notes, rate)
	}
	if f.Stability != nil {
		notes = append(notes, f.Stability.Text())
	}
	if f.UnreliableModel {
		notes = append(notes, LabelUnreliableModel)
	}
	return fmt.Sprintf("%s finding %s (%s)", f.Class, f.ID, strings.Join(notes, ", "))
}

// sarifLevel is "" for statuses that are not code-scanning alerts.
func sarifLevel(s Status) string {
	switch s {
	case StatusVerified:
		return "error"
	case StatusProbable:
		return "warning"
	}
	return ""
}

func sarifInvocationOf(r *Report) sarifInvocation {
	inv := sarifInvocation{ExecutionSuccessful: !r.Run.Incomplete, Notifications: []sarifNotification{}}
	if r.Run.Incomplete {
		inv.Notifications = append(inv.Notifications, sarifNotification{
			Descriptor: sarifDescriptor{ID: "creep/incomplete"},
			Level:      "error",
			Message:    sarifMessage{Text: "incomplete run (" + r.Run.Reason + "): not everything was evaluated; this is not a clean result"},
		})
	}
	if r.Run.UnreliableModel {
		inv.Notifications = append(inv.Notifications, sarifNotification{
			Descriptor: sarifDescriptor{ID: "creep/unreliable-model"},
			Level:      "error",
			Message:    sarifMessage{Text: UnreliableModelNote},
		})
	}
	inv.Notifications = append(inv.Notifications, incrementalNotifications(r.Incremental.Text(r.Coverage.NotEvaluated))...)
	inv.Notifications = append(inv.Notifications, sarifNotification{
		Descriptor: sarifDescriptor{ID: "creep/not-looked-for"},
		Level:      "note",
		Message:    sarifMessage{Text: "not looked for in any language: " + NotLookedForText()},
	})
	if summary := ByDesignSummary(r.Coverage.NotEvaluated); summary != "" {
		inv.Notifications = append(inv.Notifications, sarifNotification{
			Descriptor: sarifDescriptor{ID: "creep/by-design"},
			Level:      "note",
			Message:    sarifMessage{Text: "no class covers the " + summary},
		})
	}
	for _, n := range r.Coverage.NotEvaluated {
		inv.Notifications = append(inv.Notifications, sarifNotification{
			Descriptor: sarifDescriptor{ID: "creep/not-evaluated/" + string(n.Reason)},
			Level:      "warning",
			Message:    sarifMessage{Text: "file not evaluated: " + string(n.Reason)},
			Locations:  []sarifLocation{fileLocation(n.Path, 0)},
		})
	}
	inv.Notifications = append(inv.Notifications, scannerNotifications(r.Coverage.Scanners)...)
	inv.Notifications = append(inv.Notifications, verificationNotifications(r.Verification)...)
	inv.Notifications = append(inv.Notifications, baselineNotifications(r.Baseline.Text(r.Findings))...)
	return inv
}

// scannerNotifications notes each optional scanner and its classes: a note
// when it evaluated them or was not run, a warning when it failed. Names
// and classes are IDs (checkScanner).
func scannerNotifications(scanners []ScannerCoverage) []sarifNotification {
	out := make([]sarifNotification, len(scanners))
	for i, s := range scanners {
		level, verb := "note", "not evaluated"
		switch s.Status {
		case ScannerEvaluated:
			verb = "evaluated"
		case ScannerFailed:
			level = "warning"
		}
		out[i] = sarifNotification{
			Descriptor: sarifDescriptor{ID: "creep/scanner/" + string(s.Status)},
			Level:      level,
			Message:    sarifMessage{Text: scannerMessage(s, verb)},
		}
	}
	return out
}

func scannerMessage(s ScannerCoverage, verb string) string {
	text := fmt.Sprintf("optional scanner %s %s; %s: %s", s.Name, s.Status, verb, strings.Join(s.Classes, ", "))
	if note := s.SkipNote(); note != "" {
		text += "; " + note
	}
	return text
}

func fileLocation(path string, line int) sarifLocation {
	loc := sarifLocation{Physical: sarifPhysical{Artifact: sarifArtifact{URI: uriPath(path), URIBaseID: srcRoot}}}
	if line > 0 {
		loc.Physical.Region = &sarifRegion{StartLine: line}
	}
	return loc
}
