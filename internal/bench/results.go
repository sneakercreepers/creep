package bench

import (
	"encoding/json"
	"fmt"
	"strings"
)

// SchemaVersion is the version of the results JSON (ADR 0030). Adding a
// field is compatible; renaming, removing or changing a field's meaning
// bumps it.
const SchemaVersion = 1

// Results is what creep bench prints: --format json as is, text as
// Markdown. Both are published in docs/bench.
type Results struct {
	SchemaVersion int          `json:"schema_version"`
	Corpus        CorpusInfo   `json:"corpus"`
	Model         ModelInfo    `json:"model"`
	Tiers         []TierResult `json:"tiers"`
	// Unmeasured are the coverage classes no corpus case plants: the bench
	// says nothing about them, so the page names them instead of omitting.
	Unmeasured []string   `json:"unmeasured_classes"`
	Smoke      []SmokeRun `json:"smoke"`
	// Calibration is what one real calibration of the model cost, only
	// when creep bench --recalibrate ran one (#363). Added additively.
	Calibration *CalibrationCost `json:"calibration,omitempty"`
}

// CalibrationCost is one calibration's calls, tokens and wall time, and the
// tier and fitness it measured: counts and enums only.
type CalibrationCost struct {
	Calls        int     `json:"calls"`
	InputTokens  int     `json:"input_tokens"`
	OutputTokens int     `json:"output_tokens"`
	Seconds      float64 `json:"seconds"`
	Tier         string  `json:"tier"`
	Fit          bool    `json:"fit"`
	Unfit        string  `json:"unfit_reason,omitempty"`
}

func writeCalibration(b *strings.Builder, c *CalibrationCost) {
	if c == nil {
		return
	}
	verdict := "fit"
	if !c.Fit {
		verdict = "unfit (" + plain(c.Unfit) + ")"
	}
	fmt.Fprintf(b, "\nCalibration: %d calls, %d tokens in, %d out, %.0f s; tier %s, %s.\n",
		c.Calls, c.InputTokens, c.OutputTokens, c.Seconds, plain(c.Tier), verdict)
}

// CorpusInfo names the corpus measured.
type CorpusInfo struct {
	Cases  int    `json:"cases"`
	SHA256 string `json:"sha256"`
}

// ModelInfo names the model the replies came from. Synthesized is true
// when no model answered: an oracle wrote the replies from the corpus.
type ModelInfo struct {
	Contract    string `json:"contract"`
	Name        string `json:"name"`
	Synthesized bool   `json:"synthesized"`
}

// SmokeRun is a real-world app the bench names but never fetches.
type SmokeRun struct {
	Target string `json:"target"`
	Status string `json:"status"`
	Reason string `json:"reason"`
}

// smokeSkipped is why the smoke runs are not part of creep bench: they
// would need a download, and they have no ground truth to score.
const smokeSkipped = "creep downloads nothing (invariant 5) and these apps have no ground truth to score; run creep scan inside your own local clone"

// SmokeRuns lists the real-world apps of #35, each skipped with its reason.
func SmokeRuns() []SmokeRun {
	return []SmokeRun{
		{Target: "OWASP Juice Shop", Status: "skipped", Reason: smokeSkipped},
		{Target: "PyGoat", Status: "skipped", Reason: smokeSkipped},
	}
}

// JSON renders r with a trailing newline.
func (r Results) JSON() ([]byte, error) {
	out, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("bench results: %w", err)
	}
	return append(out, '\n'), nil
}

// Markdown renders r as the published page.
func (r Results) Markdown() string {
	var b strings.Builder
	b.WriteString("# creep-bench results\n\n")
	fmt.Fprintf(&b, "Corpus: %d cases, SHA-256 `%s`. Model: `%s` (%s).\n\n", r.Corpus.Cases, r.Corpus.SHA256, plain(r.Model.Name), plain(r.Model.Contract))
	if r.Model.Synthesized {
		b.WriteString("These replies are synthesized: an oracle answered every call from the corpus, so the numbers measure creep's pipeline (inventory, tripwire, planner, slicing, coverage), not a model's judgement.\n\n")
	}
	b.WriteString("Recall counts vulnerable twins found on their sink line (within 2 lines). False positives count safe twins with any probable or verified finding. Honesty counts the runs that claimed the class covered and found the planted vulnerability; a silent miss claimed covered and missed it.\n")
	writeCalibration(&b, r.Calibration)
	for _, t := range r.Tiers {
		writeTier(&b, t)
	}
	if len(r.Unmeasured) > 0 {
		fmt.Fprintf(&b, "\nNot measured, no case in the corpus: %s.\n", strings.Join(r.Unmeasured, ", "))
	}
	b.WriteString("\n## Smoke runs\n\n")
	for _, s := range r.Smoke {
		fmt.Fprintf(&b, "- %s: %s. %s.\n", s.Target, s.Status, s.Reason)
	}
	return b.String()
}

func writeTier(b *strings.Builder, t TierResult) {
	fmt.Fprintf(b, "\n## Tier %s\n\n%d runs, %d incomplete.\n\n", t.Tier, t.Runs, t.IncompleteRuns)
	b.WriteString("| Class | Recall | False positives | Honesty | Silent misses |\n|---|---|---|---|---|\n")
	for _, c := range t.Classes {
		fmt.Fprintf(b, "| %s | %s | %s | %s | %d |\n", c.Class,
			fraction(c.Detected, c.Vulnerable, c.Recall), fraction(c.FalsePositives, c.Safe, c.FalsePositiveRate),
			fraction(c.ClaimedCovered-c.SilentMisses, c.ClaimedCovered, c.Honesty), c.SilentMisses)
	}
}

// fraction prints n/d and its rate, or n/d and "none" when unmeasured.
func fraction(n, d int, rate *float64) string {
	if rate == nil {
		return fmt.Sprintf("%d/%d (none)", n, d)
	}
	return fmt.Sprintf("%d/%d (%.3f)", n, d, *rate)
}

// plain keeps the characters a model name or contract needs, so a recorded
// name cannot break the Markdown.
func plain(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x80 && (r == '.' || r == '-' || r == '_' || r == ':' || r == '/' || r == '@' ||
			(r >= '0' && r <= '9') || (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z')) {
			return r
		}
		return -1
	}, s)
}
