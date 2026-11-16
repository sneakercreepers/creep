package gateway

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
)

// Outcomes of a command call on its result line, added to the HTTP ones.
const (
	OutcomeTimeout       = "timeout"
	OutcomeCommandFailed = "command_failed"
	OutcomeToolUse       = "tool_use"
)

// Exec is Send for a command model. call.Endpoint must be cmd.Endpoint();
// call.Header is ignored (a command gets credentials only through declared
// env names). The order and guarantees are Send's: consent for the command
// endpoint, the budget and a concurrency slot, then the payload file and
// the request line written and synced before the program starts, then the
// result line. The payload goes to the program's stdin byte for byte, and
// its stdout is the reply body, with Status 200 when it exited 0 and left
// its working directory empty.
func (l *EgressLog) Exec(ctx context.Context, cmd *Command, call Call) (*Reply, error) {
	if cmd == nil {
		return nil, errors.New("gateway exec: nil command")
	}
	if call.Endpoint != cmd.endpoint {
		return nil, errors.New("gateway exec: call endpoint is not the command's endpoint")
	}
	call.Payload = bytes.Clone(call.Payload)
	if _, err := checkCall(call); err != nil {
		return nil, err
	}
	if l.consent == nil {
		return nil, fmt.Errorf("gateway call: %w", &ConsentError{Endpoint: cmd.endpoint, Err: errors.New("no consent configured")})
	}
	if err := l.consent.checkKey(cmd.endpoint); err != nil {
		return nil, fmt.Errorf("gateway call: %w", err)
	}
	t, err := l.admitKey(ctx, cmd.endpoint, call.ReserveTokens)
	if err != nil {
		return nil, err
	}
	return l.execAdmitted(ctx, cmd, call, t)
}

func (l *EgressLog) execAdmitted(ctx context.Context, cmd *Command, call Call, t *ticket) (*Reply, error) {
	id, err := l.logRequest(call, cmd.endpoint)
	if err != nil {
		t.cancel()
		return nil, err
	}
	body, runErr := cmd.run(ctx, call.Payload)
	status := 0
	if runErr == nil {
		status = http.StatusOK
	}
	t.finish(status, runErr, nil)
	if err := l.writeLine(commandResult(id, runErr)); err != nil {
		return nil, errors.Join(runErr, err)
	}
	if runErr != nil {
		return nil, fmt.Errorf("gateway call %s: %w", id, runErr)
	}
	return &Reply{ID: id, Status: status, Body: body}, nil
}

// commandResult is the result line of a command call: no HTTP status and,
// since CLIs report no usage, no tokens (the reservation stays spent).
func commandResult(id string, runErr error) resultLine {
	line := resultLine{V: logVersion, Type: "result", ID: id, Time: now(), Outcome: OutcomeResponse}
	switch {
	case runErr == nil:
	case errors.Is(runErr, ErrToolUse):
		line.Outcome = OutcomeToolUse
	case errors.Is(runErr, ErrResponseTooLarge):
		line.Outcome = OutcomeTooLarge
	case errors.Is(runErr, ErrCommandTimeout):
		line.Outcome = OutcomeTimeout
	case errors.Is(runErr, ErrCommandFailed):
		line.Outcome = OutcomeCommandFailed
	default:
		line.Outcome = OutcomeTransport
	}
	return line
}
