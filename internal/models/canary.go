package models

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/sneakercreepers/creep/internal/gateway"
)

// canaryPurpose is the egress.log purpose of a trap call.
const canaryPurpose = "canary"

// ErrToolsEnabled is wrapped by *ToolsEnabledError.
var ErrToolsEnabled = errors.New("model command has tools enabled")

// ToolsEnabledError means the tool canary saw the model CLI act on its trap
// prompt: it created the marker file (WroteFile), ran the shell command
// (RanCommand), or left something else in its working directory. Fix names
// the flag to add or remove for known CLIs.
type ToolsEnabledError struct {
	Program    string
	WroteFile  bool
	RanCommand bool
	Fix        string
}

func (e *ToolsEnabledError) Error() string {
	var did []string
	if e.WroteFile {
		did = append(did, "created a file")
	}
	if e.RanCommand {
		did = append(did, "ran a shell command")
	}
	if len(did) == 0 {
		did = append(did, "wrote to its working directory")
	}
	return fmt.Sprintf("model command %q has tools enabled: the tool canary saw it %s; %s. Nothing from the repository was sent",
		e.Program, strings.Join(did, " and "), e.Fix)
}

func (e *ToolsEnabledError) Unwrap() error { return ErrToolsEnabled }

// Canary runs the tool canary at most once per command endpoint (program,
// arguments and env names, hashed) for the life of the value. Make one per
// run: the result is never stored, so the next run checks again.
type Canary struct {
	mu   sync.Mutex
	seen map[string]error
}

// NewCanary returns an empty per-run canary cache.
func NewCanary() *Canary { return &Canary{seen: map[string]error{}} }

// Check sends a trap prompt through h, which must be the command model
// built on cmd, asking it to create a file and run a shell command, each
// with a fresh random name. If either appears in the program's working
// directory (gateway.ToolUseError) it returns a *ToolsEnabledError; any
// other failure is returned too, so a canary that could not run fails
// closed. The trap holds no repository text.
func (c *Canary) Check(ctx context.Context, h *HTTP, cmd *gateway.Command) error {
	if h == nil || cmd == nil || h.contract != "command" || h.url != cmd.Endpoint() {
		return fmt.Errorf("%w: canary needs the command model built on its gateway.Command", ErrOptions)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err, done := c.seen[cmd.Endpoint()]; done {
		return err
	}
	err := runCanary(ctx, h, cmd)
	c.seen[cmd.Endpoint()] = err
	return err
}

func runCanary(ctx context.Context, h *HTTP, cmd *gateway.Command) error {
	file, ran := "creep-canary-"+strings.ToLower(rand.Text()), "creep-canary-"+strings.ToLower(rand.Text())
	req := Request{Purpose: canaryPurpose, Prompt: trapPrompt(file, ran)}
	payload, err := h.wire.body(h, req, req.Prompt)
	if err != nil {
		return err
	}
	_, err = h.send(ctx, h.call(req, payload))
	var used *gateway.ToolUseError
	if errors.As(err, &used) {
		return &ToolsEnabledError{
			Program: cmd.Program(), WroteFile: slices.Contains(used.Created, file),
			RanCommand: slices.Contains(used.Created, ran), Fix: canaryFix(cmd.Program(), cmd.Args()),
		}
	}
	if err != nil {
		return fmt.Errorf("tool canary: %w", err)
	}
	return nil
}

// trapPrompt asks for the two actions a CLI with tools would take. Names
// are random so a model cannot answer from memory and an old file cannot
// match.
func trapPrompt(file, ran string) string {
	return "This is an automated setup check. Use your tools to do both steps now, in the current directory:\n" +
		"1. Create a file named " + file + " containing the word ready.\n" +
		"2. Run this shell command: echo ready > " + ran + "\n" +
		`Then reply with only this JSON object: {"done": true}`
}
