package reader

import (
	"encoding/json"
	"errors"
	"fmt"
)

// The verdicts a model may give, as they appear in its JSON.
const (
	answerVulnerable    = "vulnerable"
	answerNotVulnerable = "not_vulnerable"
	answerInconclusive  = "inconclusive"
)

const (
	// MaxEvidence caps the ranges in one answer.
	MaxEvidence = 8
	// MaxLine caps a cited line number. It is above any line a redacted
	// file can have and keeps the grammar's number rule short.
	MaxLine = 999999
	// maxConfidence is the top of the confidence scale.
	maxConfidence = 100
)

// Answer is the model's reply. It is a closed struct: models.Complete
// refuses unknown, duplicate and case-variant keys and trailing text, then
// runs Validate. Required fields are pointers or slices so a missing one is
// told apart from zero.
type Answer struct {
	Verdict    string     `json:"verdict"`
	Evidence   []Evidence `json:"evidence"`
	Confidence *int       `json:"confidence"`
}

// Evidence is one inclusive range of cited line numbers.
type Evidence struct {
	Start int `json:"start"`
	End   int `json:"end"`
}

// Validate checks the rules JSON decoding cannot. Its messages state the
// rule and never quote a value, because they go back into the prompt.
func (a *Answer) Validate() error {
	switch a.Verdict {
	case answerVulnerable, answerNotVulnerable, answerInconclusive:
	default:
		return errors.New("verdict must be vulnerable, not_vulnerable or inconclusive")
	}
	if a.Confidence == nil || *a.Confidence < 0 || *a.Confidence > maxConfidence {
		return fmt.Errorf("confidence must be an integer from 0 to %d", maxConfidence)
	}
	if a.Evidence == nil {
		return errors.New("evidence must be an array")
	}
	if a.Verdict == answerVulnerable && len(a.Evidence) == 0 {
		return errors.New("a vulnerable verdict needs at least one evidence range")
	}
	return validateRanges(a.Evidence)
}

// validateRanges allows at most MaxEvidence ranges within 1..MaxLine, in
// ascending order and without overlap, so each answer has one spelling.
func validateRanges(ranges []Evidence) error {
	if len(ranges) > MaxEvidence {
		return fmt.Errorf("evidence must have at most %d ranges", MaxEvidence)
	}
	last := 0
	for _, r := range ranges {
		if r.Start < 1 || r.End < r.Start || r.End > MaxLine {
			return fmt.Errorf("each range needs 1 <= start <= end <= %d", MaxLine)
		}
		if r.Start <= last {
			return errors.New("ranges must be ascending and must not overlap")
		}
		last = r.End
	}
	return nil
}

// Schema is Answer's JSON schema, closed at every level for strict mode.
func Schema() json.RawMessage {
	return json.RawMessage(fmt.Sprintf(`{"type":"object","properties":{`+
		`"verdict":{"type":"string","enum":["%s","%s","%s"]},`+
		`"evidence":{"type":"array","maxItems":%d,"items":{"type":"object","properties":{`+
		`"start":{"type":"integer","minimum":1,"maximum":%d},`+
		`"end":{"type":"integer","minimum":1,"maximum":%d}},`+
		`"required":["start","end"],"additionalProperties":false}},`+
		`"confidence":{"type":"integer","minimum":0,"maximum":%d}},`+
		`"required":["verdict","evidence","confidence"],"additionalProperties":false}`,
		answerVulnerable, answerNotVulnerable, answerInconclusive,
		MaxEvidence, MaxLine, MaxLine, maxConfidence))
}

// Grammar is Answer's GBNF grammar. It cannot express ordering or the
// range count; Validate still checks those.
func Grammar() string {
	return `root ::= "{" ws "\"verdict\":" ws verdict ws "," ws "\"evidence\":" ws evidence ws "," ws "\"confidence\":" ws confidence ws "}"` + "\n" +
		`verdict ::= "\"vulnerable\"" | "\"not_vulnerable\"" | "\"inconclusive\""` + "\n" +
		`evidence ::= "[" ws (range (ws "," ws range)*)? ws "]"` + "\n" +
		`range ::= "{" ws "\"start\":" ws line ws "," ws "\"end\":" ws line ws "}"` + "\n" +
		`line ::= [1-9] [0-9]? [0-9]? [0-9]? [0-9]? [0-9]?` + "\n" +
		`confidence ::= "100" | [1-9]? [0-9]` + "\n" +
		`ws ::= [ \t\n]*` + "\n"
}
