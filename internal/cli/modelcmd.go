package cli

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/sneakercreepers/creep/internal/config"
	"github.com/sneakercreepers/creep/internal/gateway"
	"github.com/sneakercreepers/creep/internal/models"
)

// newModelCommand opens the configured model CLI. model.run and model.env
// come only from operator layers (the project file cannot set them), and a
// program inside the current directory, the scanned repository, is refused.
func newModelCommand(m config.Model, getenv func(string) string) (*gateway.Command, error) {
	repo, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	return gateway.NewCommand(gateway.CommandOptions{
		Run: m.Run, Env: m.Env, Getenv: getenv, RepoDir: repo,
		Timeout:        time.Duration(m.TimeoutSeconds) * time.Second,
		MaxOutputBytes: m.MaxOutputBytes,
	})
}

// sessionModelOptions are the scan's model settings for either contract.
// Only HTTP contracts read CREEP_API_KEY; a CLI gets keys via model.env.
func sessionModelOptions(m config.Model, cmd *gateway.Command, send models.SendFunc) (models.Options, error) {
	if m.Contract != "command" {
		key, err := models.KeyFromEnv(os.Getenv)
		if err != nil {
			return models.Options{}, err
		}
		return modelOptions(m, key, send), nil
	}
	if cmd == nil {
		return models.Options{}, errors.New("contract command: the model command is not open")
	}
	return commandModelOptions(m, cmd, send), nil
}

// commandModelOptions mirror modelOptions for a CLI: the schema travels in
// the prompt, so the only structured mode is the prompt.
func commandModelOptions(m config.Model, cmd *gateway.Command, send models.SendFunc) models.Options {
	name := m.Name
	if name == "" {
		name = "command"
	}
	return models.Options{
		Contract: "command", Endpoint: cmd.Endpoint(), Model: name,
		Structured: models.StructuredPrompt, MaxOutputTokens: replyTokens, Retries: 1, Send: send,
	}
}

// checkTools runs the tool canary on a command model before anything from
// the repository is sent. It uses the link's own send, not the recording
// cache, so the trap always reaches the CLI. A replayed run starts no
// program, so it has nothing to check.
func checkTools(ctx context.Context, canary *models.Canary, m config.Model, link modelLink) error {
	if link.command == nil {
		return nil
	}
	h, err := models.NewHTTP(commandModelOptions(m, link.command, link.send))
	if err != nil {
		return err
	}
	return canary.Check(ctx, h, link.command)
}
