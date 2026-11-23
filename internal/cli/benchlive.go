package cli

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/sneakercreepers/creep/internal/bench"
	"github.com/sneakercreepers/creep/internal/config"
	"github.com/sneakercreepers/creep/internal/exitcode"
	"github.com/sneakercreepers/creep/internal/gateway"
	"github.com/sneakercreepers/creep/internal/models"
	"github.com/sneakercreepers/creep/internal/state"
)

// benchFixtureFile is where --record writes the run's fixture: in the run
// directory under .creep/runs, for a maintainer to review and publish.
const benchFixtureFile = "bench-fixture.json"

// benchLive is one live bench run's open resources.
type benchLive struct {
	store *state.Store
	run   *state.Run
	link  modelLink
}

func (b *benchLive) close() {
	if b.link.close != nil {
		_ = b.link.close()
	}
	if b.run != nil {
		_ = b.run.Close()
	}
	if b.store != nil {
		_ = b.store.Close()
	}
}

// runBenchLive runs the corpus against the configured model through the
// gateway: consent, budget and egress.log apply as in a scan, in a run
// directory of ./.creep. Only HTTP contracts are supported, because a
// fixture must rebuild the client that made its request bodies. --record
// also writes the fixture --replay would need to reproduce this run.
func runBenchLive(e env, cases []bench.Case) int {
	r, err := loadConfig(e.opts)
	if err == nil {
		err = checkBenchModel(r.Config.Model)
	}
	if err != nil {
		printError(e.stderr, "creep bench", err)
		return exitcode.ConfigError
	}
	b := &benchLive{}
	defer b.close()
	if err := b.open(e, r); err != nil {
		printError(e.stderr, "creep bench", err)
		return exitcode.ConfigError
	}
	return b.measure(e, r.Config.Model, cases)
}

func checkBenchModel(m config.Model) error {
	if m.Contract == "command" {
		return errors.New("model.contract command is not supported: a recorded run must rebuild its HTTP client; use openai or anthropic")
	}
	return checkModelConfig(m)
}

func (b *benchLive) open(e env, r *config.Resolved) error {
	mode := state.ModeLive
	if e.opts.record {
		mode = state.ModeRecord
	}
	var err error
	if b.store, err = state.OpenUser(stateDir); err != nil {
		return err
	}
	if b.run, err = b.store.NewRun(mode); err != nil {
		return err
	}
	b.link, err = e.deps.connect(r, b.run.Dir(), e.stderr)
	return err
}

// measure runs the bench, then ends the run, writes the fixture for
// --record and prints the results.
func (b *benchLive) measure(e env, cfg config.Model, cases []bench.Case) int {
	rec := bench.NewRecorder()
	opts, err := sessionModelOptions(cfg, nil, recordingSend(rec, b.link.send))
	if err != nil {
		printError(e.stderr, "creep bench", err)
		return exitcode.ConfigError
	}
	m, err := models.NewHTTP(opts)
	if err != nil {
		printError(e.stderr, "creep bench", err)
		return exitcode.ConfigError
	}
	fmt.Fprintf(e.stderr, "creep bench: sends %d corpus files, each redacted, to endpoint %s, once per tier\n",
		len(cases)*len(bench.Variants()), escapeControl(cfg.Endpoint))
	outcomes, err := benchAll(context.Background(), m, cases)
	if err != nil {
		_ = b.run.Finish(state.OutcomeIncomplete, "model_failed")
		printError(e.stderr, "creep bench", err)
		return failureCode(err)
	}
	clients := benchClients{model: m, fixture: fixtureModel(cfg.Endpoint, m)}
	if err := b.finish(e, rec.Fixture(clients.fixture, false)); err != nil {
		printError(e.stderr, "creep bench", err)
		return exitcode.ConfigError
	}
	return printBench(e, clients, cases, outcomes)
}

// finish ends the run and, for --record, writes fix into its directory.
func (b *benchLive) finish(e env, fix bench.Fixture) error {
	if err := b.run.Finish(state.OutcomeComplete, ""); err != nil {
		return err
	}
	if !e.opts.record {
		return nil
	}
	data, err := fix.JSON()
	if err != nil {
		return err
	}
	root, err := os.OpenRoot(b.run.Dir())
	if err != nil {
		return fmt.Errorf("bench fixture: %w", err)
	}
	defer root.Close()
	if err := root.WriteFile(benchFixtureFile, data, 0o600); err != nil {
		return fmt.Errorf("bench fixture: %w", err)
	}
	fmt.Fprintf(e.stderr, "creep bench: recorded %d replies in %s; review it before publishing it as internal/bench/fixtures/published.json\n",
		len(fix.Replies), escapeControl(b.run.Dir()+string(os.PathSeparator)+benchFixtureFile))
	return nil
}

// recordingSend serves a body asked before with its first reply, so the
// run and its replay agree, and records every 200 reply.
func recordingSend(rec *bench.Recorder, send models.SendFunc) models.SendFunc {
	return func(ctx context.Context, c gateway.Call) (*gateway.Reply, error) {
		if body, ok := rec.Lookup(c.Payload); ok {
			return &gateway.Reply{ID: "replay", Status: 200, Body: body}, nil
		}
		r, err := send(ctx, c)
		if err == nil && r.Status == 200 {
			rec.Record(c.Payload, r.Body)
		}
		return r, err
	}
}
