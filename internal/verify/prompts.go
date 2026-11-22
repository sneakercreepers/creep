package verify

import (
	_ "embed" // the system prompts are versioned data in prompts/
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// PromptVersion names the prompts in prompts/ and the PoC schema. A change
// to either bumps it, so a recorded PoC says what produced it.
const PromptVersion = 1

// Tier selects the prompt variant. It mirrors calibrate.Tier, which verify
// may not import; the caller converts with Tier(t).
type Tier string

const (
	TierS Tier = "S"
	TierM Tier = "M"
	TierL Tier = "L"
)

// ErrTier means a tier has no prompt. There is no fallback.
var ErrTier = errors.New("verify: unknown tier")

var (
	//go:embed prompts/s.txt
	systemS string
	//go:embed prompts/m.txt
	systemM string
	//go:embed prompts/l.txt
	systemL string
)

// promptBudget is the most tokens each tier's system prompt plus the PoC
// schema may take, counted as bytes. Raising one is a reviewed change.
var promptBudget = map[Tier]int{TierS: 4000, TierM: 4600, TierL: 5100}

// System returns the PoC system prompt for tier.
func System(tier Tier) (string, error) {
	switch tier {
	case TierS:
		return systemS, nil
	case TierM:
		return systemM, nil
	case TierL:
		return systemL, nil
	}
	return "", fmt.Errorf("%w %q", ErrTier, string(tier))
}

// classTemplates are the templates whose oracle proves each class: a
// delay or marker table for SQL injection, the planted canary file for
// path traversal, the probe unescaped in HTML for template injection that
// reaches a page. A class with none gets no PoC and stays probable; a PoC
// of another template proves nothing about the class.
var classTemplates = map[string][]string{
	"sqli":               {TemplateSQLPayload},
	"path_traversal":     {TemplatePathPayload},
	"template_injection": {TemplateHTTPRequest, TemplateHTTPSequence},
}

// TemplatesFor is the templates a PoC for class may use; nil when no
// template's oracle proves it.
func TemplatesFor(class string) []string { return slices.Clone(classTemplates[class]) }

// Fits reports whether p's template proves class.
func Fits(class string, p PoC) bool { return slices.Contains(classTemplates[class], p.Template()) }

// UserPrompt is the PoC request's user turn: the finding's class, the
// templates allowed for it and the code the reader saw. code must be
// redact.File output only (the reader's slice).
func UserPrompt(class, code string) (string, error) {
	allowed := classTemplates[class]
	if len(allowed) == 0 {
		return "", fmt.Errorf("verify: class %q has no PoC template: %w", class, ErrInvalid)
	}
	return "FINDING\nclass: " + class + "\ntemplates: " + strings.Join(allowed, ", ") + "\n\n" + code, nil
}

// Schema is Request's JSON schema, closed at every level for strict mode.
// The three templates not chosen are null. Validate still checks every
// rule the schema cannot state.
func Schema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{` +
		`"template":{"type":"string","enum":["http_request","http_sequence","sql_payload","path_payload"]},` +
		`"http_request":` + nullable(`"request":`+callRef+`,"oracle":`+oracleRef, `"request","oracle"`) + `,` +
		`"http_sequence":` + nullable(`"auth":`+callRef+`,"session":{"type":"string","enum":["cookie","bearer"]},`+
		`"token_field":{"type":"string","maxLength":64},"request":`+callRef+`,"oracle":`+oracleRef,
		`"auth","session","token_field","request","oracle"`) + `,` +
		`"sql_payload":` + nullable(`"request":`+callRef+`,"context":{"type":"string","enum":["string","numeric"]},`+
		`"technique":{"type":"string","enum":["delay","marker"]}`, `"request","context","technique"`) + `,` +
		`"path_payload":` + nullable(`"request":`+callRef+`,"style":{"type":"string","enum":["relative","encoded","absolute"]},`+
		`"depth":{"type":"integer","minimum":0,"maximum":12}`, `"request","style","depth"`) +
		`},"required":["template","http_request","http_sequence","sql_payload","path_payload"],"additionalProperties":false,` +
		`"$defs":{"call":` + callSchema + `,"oracle":` + oracleSchema + `}}`)
}

// References to the shared definitions, so each is sent once.
const (
	callRef   = `{"$ref":"#/$defs/call"}`
	oracleRef = `{"$ref":"#/$defs/oracle"}`
)

func nullable(properties, required string) string {
	return `{"anyOf":[{"type":"null"},{"type":"object","properties":{` + properties +
		`},"required":[` + required + `],"additionalProperties":false}]}`
}

var callSchema = `{"type":"object","properties":{` +
	`"method":{"type":"string","enum":["GET","POST","PUT","PATCH","DELETE"]},` +
	`"path":{"type":"string","maxLength":1024},` +
	`"headers":{"type":"array","maxItems":8,"items":{"type":"object","properties":{` +
	`"name":{"type":"string","enum":["` + strings.Join(allowedHeaders, `","`) + `"]},` +
	`"value":{"type":"string","maxLength":1024}},"required":["name","value"],"additionalProperties":false}},` +
	`"content_type":{"type":"string","enum":["","json","form","text"]},` +
	`"body":{"type":"string","maxLength":8192}},` +
	`"required":["method","path","headers","content_type","body"],"additionalProperties":false}`

const oracleSchema = `{"type":"object","properties":{` +
	`"kind":{"type":"string","enum":["reflect"]},"status":{"type":"integer","minimum":0,"maximum":599}},` +
	`"required":["kind","status"],"additionalProperties":false}`
