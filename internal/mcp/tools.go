package mcp

import (
	"context"
	"errors"
	"fmt"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/sneakercreepers/creep/internal/exitcode"
	"github.com/sneakercreepers/creep/internal/report"
)

// reportPath is where every tool reads the last scan.
const reportPath = ".creep/report.json"

// maxScanFindings bounds the findings a scan reply lists; the findings
// tool pages through the rest.
const maxScanFindings = 50

// Finding is one finding as the tools list it. Path, class and reason
// come from the scanned repository: Path is escaped, the others are
// report IDs, which hold no free text.
type Finding struct {
	ID         string `json:"id"`
	Class      string `json:"class"`
	Status     string `json:"status"`
	Path       string `json:"path"`
	Line       int    `json:"line"`
	Confidence int    `json:"confidence,omitempty"`
	Reason     string `json:"reason,omitempty"`
	Partial    bool   `json:"partial,omitempty"`
	Suppressed bool   `json:"suppressed,omitempty"`
}

// ScanResult is the scan tool's reply.
type ScanResult struct {
	ExitCode     int       `json:"exit_code"`
	Outcome      string    `json:"outcome"`
	Report       string    `json:"report,omitempty"`
	Findings     []Finding `json:"findings"`
	More         int       `json:"more,omitempty"`
	NotEvaluated int       `json:"not_evaluated"`
	Log          string    `json:"log,omitempty"`
}

// FindingsResult is one page of the findings tool.
type FindingsResult struct {
	Total    int       `json:"total"`
	Findings []Finding `json:"findings"`
}

// WhyResult is the why tool's reply: the finding and the lines behind it.
// creep proposes no fix yet; one would come back here as a unified diff for
// the host agent to show, never applied (ADR 0027).
type WhyResult struct {
	Finding   Finding            `json:"finding"`
	Evidence  []report.LineRange `json:"evidence,omitempty"`
	Stability string             `json:"stability,omitempty"`
	Note      string             `json:"note,omitempty"`
}

type tools struct{ b Backend }

func (t tools) scan(ctx context.Context, _ *sdk.CallToolRequest, a ScanArgs) (*sdk.CallToolResult, ScanResult, error) {
	if err := checkChanged(a.Changed); err != nil {
		return nil, ScanResult{}, err
	}
	run, err := t.b.Scan(ctx, a.Changed)
	if err != nil {
		return nil, ScanResult{}, safeError("scan", err)
	}
	res := ScanResult{ExitCode: run.ExitCode, Outcome: outcome(run.ExitCode), Log: report.Visible(run.Log), Findings: []Finding{}}
	// A scan that fails before its report (exit 2 or 3) writes none, and
	// the report on disk would be an older scan's.
	if !wroteReport(run.ExitCode) {
		return nil, res, nil
	}
	rep, err := t.b.LastReport()
	if err != nil {
		return nil, ScanResult{}, safeError("scan: read the report", err)
	}
	res.Report, res.NotEvaluated = reportPath, len(rep.Coverage.NotEvaluated)
	for i, f := range rep.Findings {
		if i == maxScanFindings {
			res.More = len(rep.Findings) - i
			break
		}
		res.Findings = append(res.Findings, summarize(f))
	}
	return nil, res, nil
}

func (t tools) findings(_ context.Context, _ *sdk.CallToolRequest, a FindingsArgs) (*sdk.CallToolResult, FindingsResult, error) {
	status, offset, limit, err := a.page()
	if err != nil {
		return nil, FindingsResult{}, err
	}
	rep, err := t.b.LastReport()
	if err != nil {
		return nil, FindingsResult{}, safeError("findings", err)
	}
	res := FindingsResult{Findings: []Finding{}}
	for _, f := range rep.Findings {
		if status != "" && f.Status != status {
			continue
		}
		res.Total++
		if res.Total > offset && len(res.Findings) < limit {
			res.Findings = append(res.Findings, summarize(f))
		}
	}
	return nil, res, nil
}

func (t tools) why(_ context.Context, _ *sdk.CallToolRequest, a WhyArgs) (*sdk.CallToolResult, WhyResult, error) {
	if !report.ValidID(a.ID) {
		return nil, WhyResult{}, fmt.Errorf("invalid finding ID %s", quote(a.ID))
	}
	rep, err := t.b.LastReport()
	if err != nil {
		return nil, WhyResult{}, safeError("why", err)
	}
	f, ok := rep.Finding(a.ID)
	if !ok {
		return nil, WhyResult{}, fmt.Errorf("no finding %s in %s", a.ID, reportPath)
	}
	res := WhyResult{Finding: summarize(f), Evidence: f.Evidence, Stability: f.Stability.Text()}
	if f.Partial {
		res.Note = "the reader saw a partial slice: lines were left out, so this verdict is partial coverage"
	}
	return nil, res, nil
}

func summarize(f report.Finding) Finding {
	return Finding{
		ID: f.ID, Class: f.Class, Status: string(f.Status), Path: report.Visible(f.Path), Line: f.Line,
		Confidence: f.Confidence, Reason: f.Reason, Partial: f.Partial, Suppressed: f.Suppression != nil,
	}
}

func wroteReport(code int) bool {
	return code == exitcode.OK || code == exitcode.GateExceeded || code == exitcode.Incomplete
}

// outcome names an exit code (ADR 0007) for the calling agent.
func outcome(code int) string {
	switch code {
	case exitcode.OK:
		return "ok"
	case exitcode.GateExceeded:
		return "gate_exceeded"
	case exitcode.ConfigError:
		return "usage_or_config_error"
	case exitcode.ModelOrSandbox:
		return "model_error"
	case exitcode.Incomplete:
		return "incomplete"
	}
	return "unknown"
}

// maxErrorBytes bounds an error sent to the caller.
const maxErrorBytes = 1024

// safeError escapes and bounds a backend error: it can carry repository
// paths and file system names, which must reach the caller as data.
func safeError(tool string, err error) error {
	msg := err.Error()
	if len(msg) > maxErrorBytes {
		msg = msg[:maxErrorBytes] + "..."
	}
	return errors.New(tool + ": " + report.Visible(msg))
}
