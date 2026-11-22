package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/sneakercreepers/creep/internal/calibrate"
	"github.com/sneakercreepers/creep/internal/config"
	"github.com/sneakercreepers/creep/internal/gateway"
	"github.com/sneakercreepers/creep/internal/models"
	"github.com/sneakercreepers/creep/internal/planner"
	"github.com/sneakercreepers/creep/internal/reader"
	"github.com/sneakercreepers/creep/internal/sandbox"
	"github.com/sneakercreepers/creep/internal/scanrun"
	"github.com/sneakercreepers/creep/internal/state"
)

// scanDeps are the parts of a scan that reach outside the process: the
// model transport and the calibration cache. Run uses productionDeps; CLI
// tests pass fakes, so every scan path runs with no network and no key.
type scanDeps struct {
	connect   func(r *config.Resolved, runDir string, stderr io.Writer) (modelLink, error)
	calibrate func(ctx context.Context, opts calibrate.CacheOptions) (calibrate.Calibration, error)
	now       func() time.Time // --stats clock; nil is time.Now
	date      func() time.Time // the baseline's today (#27); nil is time.Now
	// runScanner runs one optional scanner; nil is scanrun.Run, the only
	// code that starts a program (ADR 0013).
	runScanner func(ctx context.Context, job scanrun.Job) scanrun.Result
	sandbox    sandboxDeps
	// planned sees the planner input scan builds; nil in production. The
	// holistic protection test walks the real input through it (#188).
	planned func(planner.Input)
}

// scannerRunner is runScanner, or scanrun.Run when none is set.
func (d scanDeps) scannerRunner() func(context.Context, scanrun.Job) scanrun.Result {
	if d.runScanner != nil {
		return d.runScanner
	}
	return scanrun.Run
}

// modelLink is the model transport of one run.
type modelLink struct {
	send    models.SendFunc
	command *gateway.Command // the model CLI for contract command; nil for HTTP
	egress  string           // egress.log path for the data-handling section; "" if none
	close   func() error
}

func productionDeps() scanDeps {
	return scanDeps{
		connect: connectGateway, calibrate: calibrateWithUserCache, now: time.Now,
		sandbox: sandboxDeps{detect: sandbox.Detect, clean: sandbox.Clean, images: sandbox.Images, open: openSandbox},
	}
}

// connectGateway is the only production transport: consent, budget,
// write-ahead egress.log and the allowlisted client, in the run directory.
// A command model runs through the same log with gateway.EgressLog.Exec.
func connectGateway(r *config.Resolved, runDir string, stderr io.Writer) (modelLink, error) {
	cfg := r.Config
	var cmd *gateway.Command
	if cfg.Model.Contract == "command" {
		var err error
		if cmd, err = newModelCommand(cfg.Model, os.Getenv); err != nil {
			return modelLink{}, err
		}
	}
	consent, err := gateway.NewConsent(gateway.ConsentOptions{
		CI: config.InCI(os.Getenv), Policy: r.PolicyConsent(),
		StorePath: userFile("consent.json"), Prompt: gateway.TerminalPrompt(os.Stdin, stderr),
	})
	if err != nil {
		return modelLink{}, err
	}
	budget, err := gateway.NewBudget(gateway.BudgetOptions{MaxTokens: cfg.Budget.MaxTokens, MaxCalls: cfg.Budget.MaxCalls})
	if err != nil {
		return modelLink{}, err
	}
	log, err := gateway.OpenEgressLog(runDir, consent, budget)
	if err != nil {
		return modelLink{}, err
	}
	egress := filepath.Join(runDir, "egress.log")
	if cmd != nil {
		return modelLink{send: models.ThroughCommand(log, cmd), command: cmd, egress: egress, close: log.Close}, nil
	}
	client, err := gateway.NewClient(gateway.Options{Allow: cfg.Egress.Allow})
	if err != nil {
		_ = log.Close()
		return modelLink{}, err
	}
	closeAll := func() error { client.CloseIdleConnections(); return log.Close() }
	return modelLink{send: models.Through(log, client), egress: egress, close: closeAll}, nil
}

// userFile is a file in the user's creep config directory, or "" (keep
// consent for this run only) when there is none.
func userFile(name string) string {
	base, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(base, "creep", name)
}

// calibrateWithUserCache keeps calibrations in the user's cache directory:
// they measure the model, not the scanned repository.
func calibrateWithUserCache(ctx context.Context, opts calibrate.CacheOptions) (calibrate.Calibration, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return calibrate.Calibration{}, fmt.Errorf("calibration cache: %w", err)
	}
	store, err := state.OpenUser(filepath.Join(base, "creep"))
	if err != nil {
		return calibrate.Calibration{}, err
	}
	defer store.Close()
	opts.Store, opts.Now = store, time.Now
	return calibrate.RunCached(ctx, opts)
}

// errNotRecordable marks a reply the store must not record (not 200).
var errNotRecordable = errors.New("reply not recordable")

// recordedSend puts the run-state cache in front of send: --replay serves
// only recordings and never calls send, --record always calls and records,
// and the default serves this user's recordings and records new ones. Keys
// hash the exact request body, so a changed prompt, slice or model misses.
func recordedSend(store *state.Store, mode state.Mode, send models.SendFunc) models.SendFunc {
	return func(ctx context.Context, c gateway.Call) (*gateway.Reply, error) {
		// A replayed answer needs no transport to notice a done context, so
		// the scan deadline is checked here too (#260).
		if ctx.Err() != nil {
			return nil, fmt.Errorf("model call: %w", context.Cause(ctx))
		}
		var live *gateway.Reply
		body, err := store.Respond(mode, cacheKey(c), func() ([]byte, error) {
			r, err := send(ctx, c)
			if err != nil {
				return nil, err
			}
			live = r
			if r.Status != 200 {
				return nil, errNotRecordable
			}
			return r.Body, nil
		})
		switch {
		case errors.Is(err, errNotRecordable):
			return live, nil
		case err != nil:
			return nil, err
		case live != nil:
			return live, nil
		}
		return &gateway.Reply{ID: "replay", Status: 200, Body: body}, nil
	}
}

// cacheKey names a recording by the exact body, the model and where the
// call went: c.Model is "command" for every model CLI, and one model name
// can sit behind two endpoints, so the endpoint (a URL, or the command's
// hash of path, arguments and environment names) keeps an answer recorded
// for one from being served for another (pentest P8). The endpoint goes
// into the content hash, ahead of the body and a NUL no URL holds, so any
// URL fits the key's character set and length.
func cacheKey(c gateway.Call) state.Key {
	h := sha256.New()
	h.Write([]byte(c.Endpoint + "\x00"))
	h.Write(c.Payload)
	return state.Key{
		ContentHash:   hex.EncodeToString(h.Sum(nil)),
		Model:         c.Model,
		PromptVersion: fmt.Sprintf("%s.r%d.c%d", c.Purpose, reader.PromptVersion, calibrate.PromptVersion),
	}
}
