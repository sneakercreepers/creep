package models

import (
	"bytes"
	"context"
	"strings"

	"github.com/sneakercreepers/creep/internal/gateway"
)

// commandWire is the command contract: the prompt as plain text on stdin,
// the model's JSON object alone on stdout. A CLI has no structured-output
// switch creep can rely on, so the schema travels in the prompt and the
// reply gets the same strict decoding as an HTTP reply.
type commandWire struct{}

// ThroughCommand runs every call with log.Exec, so consent, the budget,
// egress.log and the process limits apply as they do for HTTP.
func ThroughCommand(log *gateway.EgressLog, cmd *gateway.Command) SendFunc {
	return func(ctx context.Context, call gateway.Call) (*gateway.Reply, error) {
		return log.Exec(ctx, cmd, call)
	}
}

func (commandWire) path() string { return "" }

func (commandWire) supports(s Structured) bool { return s == StructuredPrompt }

// headers is empty: a CLI gets credentials only from env names the user
// declared (model.env), never from creep.
func (commandWire) headers(Key) map[string][]string { return nil }

func (commandWire) body(_ *HTTP, req Request, prompt string) ([]byte, error) {
	var b strings.Builder
	if req.System != "" {
		b.WriteString(req.System)
		b.WriteString("\n\n")
	}
	b.WriteString(prompt)
	if len(req.Schema) > 0 {
		b.WriteString("\n\nReply with only one JSON object, no prose and no code fence, that matches this JSON schema:\n")
		b.Write(bytes.TrimSpace(req.Schema))
	}
	return []byte(b.String()), nil
}

// parse takes stdout as the model's output. An empty stdout is an invalid
// reply (retried), not a malformed envelope: a CLI has no envelope.
func (commandWire) parse(body []byte, _ Structured) (reply, error) {
	if len(bytes.TrimSpace(body)) == 0 {
		return reply{problem: reasonEmpty}, nil
	}
	return reply{content: body}, nil
}

// usage is never known: CLIs do not report tokens on the contract, so the
// call's reservation stays spent.
func (commandWire) usage([]byte) (gateway.Usage, bool) { return gateway.Usage{}, false }
