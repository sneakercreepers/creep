package cli

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/sneakercreepers/creep/internal/bench"
	"github.com/sneakercreepers/creep/internal/gateway"
)

// oracleKinds is the discovery sink kind a correct model names for each
// class; a class with none (idor) gets no proposal.
var oracleKinds = map[string]string{
	"sqli": "sql", "command_injection": "shell", "path_traversal": "file",
	"ssrf": "http_client", "nosql_injection": "nosql", "template_injection": "template",
}

// benchOracle is the synthesized model behind the published fixture: it
// knows the corpus, finds which twin a request shows, and answers as a
// model that is always right would. It never sees a case ID or label in
// the request; it recognizes the code.
type benchOracle struct {
	cases []bench.Case
	calls int
}

type oracleTwin struct {
	c bench.Case
	v bench.Variant
}

func (o *benchOracle) send(_ context.Context, c gateway.Call) (*gateway.Reply, error) {
	o.calls++
	prompt := userContent(c.Payload)
	answer, err := o.answer(prompt)
	if err != nil {
		return nil, err
	}
	body, err := chatReply(answer)
	return &gateway.Reply{ID: "oracle", Status: 200, Body: body}, err
}

func (o *benchOracle) answer(prompt string) (map[string]any, error) {
	if secs := discoverySections(prompt); len(secs) > 0 {
		return o.discovery(secs)
	}
	if m := hypothesisLine.FindStringSubmatch(prompt); m != nil {
		return o.verdict(prompt, m[1], m[3])
	}
	return nil, errors.New("oracle: neither a discovery nor a reader request")
}

// discovery reports the canary and, for the twin's section, its entry
// point and its sink with the class's kind.
func (o *benchOracle) discovery(secs []discoverySection) (map[string]any, error) {
	answer, ok := promptAnswerFor(secs)
	if !ok {
		return nil, errors.New("oracle: no canary in the discovery request")
	}
	canary, _, _, _ := canaryAt(secs)
	for _, s := range secs {
		if s.num == canary {
			continue
		}
		shown := map[int]string{}
		for i, l := range s.lines {
			shown[i+1] = l
		}
		twins := o.twinsShowing(shown, len(s.lines))
		if len(twins) != 1 {
			return nil, fmt.Errorf("oracle: %d twins match a discovery file", len(twins))
		}
		o.propose(answer, s.num, len(s.lines), twins[0])
	}
	return answer, nil
}

// promptAnswerFor is promptAnswer's canary-only reply, from parsed
// sections.
func promptAnswerFor(secs []discoverySection) (map[string]any, bool) {
	file, entry, sink, found := canaryAt(secs)
	if !found {
		return nil, false
	}
	return map[string]any{
		"entries": []any{map[string]any{"file": file, "start": entry, "end": entry + 2, "kind": "http"}},
		"sinks":   []any{map[string]any{"file": file, "line": sink, "kind": "file", "entry": 0}},
		"auth":    []any{},
	}, true
}

func (o *benchOracle) propose(answer map[string]any, file, lines int, t oracleTwin) {
	twin := t.c.Twin(t.v)
	entries := answer["entries"].([]any)
	entry := len(entries)
	answer["entries"] = append(entries, map[string]any{"file": file, "start": twin.Entry, "end": lines, "kind": "http"})
	if kind, ok := oracleKinds[t.c.Class]; ok {
		sinks := answer["sinks"].([]any)
		answer["sinks"] = append(sinks, map[string]any{"file": file, "line": twin.Sink, "kind": kind, "entry": entry})
	}
}

// verdict is vulnerable only for the planted class on the vulnerable
// twin's sink line; everything else is not_vulnerable. Code shown the same
// in both twins (lines above the fix) is answered for the safe one, as a
// model seeing only those lines could not tell them apart.
func (o *benchOracle) verdict(prompt, class, sinkText string) (map[string]any, error) {
	twins := o.twinsShowing(codeLines(prompt), 0)
	if len(twins) == 0 {
		return nil, errors.New("oracle: no twin matches the code shown")
	}
	sink, err := strconv.Atoi(sinkText)
	if err != nil {
		return nil, err
	}
	if class == "sql_injection" {
		class = "sqli" // the reader's name for the report's sqli
	}
	verdict, confidence := "vulnerable", 90
	for _, t := range twins {
		if t.v != bench.Vulnerable || class != t.c.Class || sink != t.c.Twin(t.v).Sink {
			verdict, confidence = "not_vulnerable", 80
		}
	}
	return map[string]any{"verdict": verdict, "evidence": []map[string]int{{"start": sink, "end": sink}}, "confidence": confidence}, nil
}

// codeLines reads the numbered CODE lines of a reader request.
func codeLines(prompt string) map[int]string {
	shown := map[int]string{}
	_, code, _ := strings.Cut(prompt, "\nCODE:\n")
	for _, line := range strings.Split(code, "\n") {
		num, text, ok := strings.Cut(line, "| ")
		n, err := strconv.Atoi(num)
		if ok && err == nil {
			shown[n] = text
		}
	}
	return shown
}

// twinsShowing are the twins whose source holds every shown line at its
// number (and, when total is set, has exactly total lines).
func (o *benchOracle) twinsShowing(shown map[int]string, total int) []oracleTwin {
	var found []oracleTwin
	for _, c := range o.cases {
		for _, v := range bench.Variants() {
			if showsTwin(shown, total, c.Twin(v).Source) {
				found = append(found, oracleTwin{c, v})
			}
		}
	}
	return found
}

func showsTwin(shown map[int]string, total int, src []byte) bool {
	lines := strings.Split(strings.TrimSuffix(string(src), "\n"), "\n")
	if len(shown) == 0 || (total > 0 && total != len(lines)) {
		return false
	}
	for n, text := range shown {
		if n < 1 || n > len(lines) || lines[n-1] != text {
			return false
		}
	}
	return true
}
