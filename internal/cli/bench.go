package cli

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/sneakercreepers/creep/internal/bench"
	"github.com/sneakercreepers/creep/internal/calibrate"
	"github.com/sneakercreepers/creep/internal/exitcode"
	"github.com/sneakercreepers/creep/internal/gateway"
	"github.com/sneakercreepers/creep/internal/models"
)

// errNoPublishedReply is a --replay request the published fixture has no
// reply for: the corpus, a prompt or the client changed since it was made.
var errNoPublishedReply = errors.New("no published reply for this request")

// benchClients is the bench's model and where its replies came from.
type benchClients struct {
	model       *models.HTTP
	fixture     bench.FixtureModel
	synthesized bool
	misses      *int // --replay requests with no published reply
}

// runBench runs creep-bench (ADR 0030): every corpus case, both twins, at
// tiers S, M and L, through the scan pipeline, then prints recall, false
// positives and honesty per class. --replay serves the published fixture
// only; without it the configured model answers through the gateway.
func runBench(e env, args []string) int {
	if len(args) > 0 {
		printError(e.stderr, "creep bench", fmt.Errorf("takes no arguments (got %d)", len(args)))
		return exitcode.ConfigError
	}
	if e.opts.format == "sarif" {
		printError(e.stderr, "creep bench", errors.New("prints text, markdown or json, not sarif"))
		return exitcode.ConfigError
	}
	cases, err := bench.Corpus()
	if err != nil {
		printError(e.stderr, "creep bench", err)
		return exitcode.ConfigError
	}
	if e.opts.replay {
		return runBenchReplay(e, cases)
	}
	return runBenchLive(e, cases)
}

// runBenchReplay reproduces the published numbers with no network, no key,
// no state and no config: the client is built from the fixture's own
// settings, so its request bodies are the ones the fixture recorded.
func runBenchReplay(e env, cases []bench.Case) int {
	fix, err := bench.Published()
	if err != nil {
		printError(e.stderr, "creep bench", err)
		return exitcode.ModelOrSandbox
	}
	return replayFixture(e, cases, fix)
}

// replayFixture runs the bench from fix alone; a request it has no reply
// for fails the bench (exit 3) instead of scoring a gap.
func replayFixture(e env, cases []bench.Case, fix bench.Fixture) int {
	clients, err := replayClients(fix)
	if err != nil {
		printError(e.stderr, "creep bench", err)
		return exitcode.ModelOrSandbox
	}
	outcomes, err := benchAll(context.Background(), clients.model, cases)
	if err == nil && *clients.misses > 0 {
		err = fmt.Errorf("%d requests: %w; regenerate the fixture (go test ./internal/cli -run TestBenchPublished -update)", *clients.misses, errNoPublishedReply)
	}
	if err != nil {
		printError(e.stderr, "creep bench", err)
		return exitcode.ModelOrSandbox
	}
	return printBench(e, clients, cases, outcomes)
}

// replayClients answers every call from fix and counts what it lacks.
func replayClients(fix bench.Fixture) (benchClients, error) {
	replies, misses := fix.Index(), 0
	send := func(_ context.Context, c gateway.Call) (*gateway.Reply, error) {
		body, ok := replies[bench.RequestHash(c.Payload)]
		if !ok {
			misses++
			return nil, errNoPublishedReply
		}
		return &gateway.Reply{ID: "replay", Status: 200, Body: body}, nil
	}
	m, err := models.NewHTTP(fixtureOptions(fix.Model, send))
	if err != nil {
		return benchClients{}, fmt.Errorf("bench fixture model: %w", err)
	}
	return benchClients{model: m, fixture: fix.Model, synthesized: fix.Synthesized, misses: &misses}, nil
}

// fixtureOptions are the client settings a fixture was recorded with.
func fixtureOptions(m bench.FixtureModel, send models.SendFunc) models.Options {
	return models.Options{
		Contract: m.Contract, Endpoint: m.Endpoint, Model: m.Name, Structured: models.Structured(m.Structured),
		MaxOutputTokens: m.MaxOutputTokens, Retries: m.Retries, Send: send,
	}
}

// fixtureModel describes a client for the fixture header.
func fixtureModel(endpoint string, m *models.HTTP) bench.FixtureModel {
	id, set := m.Identity(), m.Settings()
	return bench.FixtureModel{
		Contract: id.Contract, Endpoint: endpoint, Name: id.Model, Structured: string(set.Structured),
		MaxOutputTokens: set.MaxOutputTokens, Retries: set.Retries,
	}
}

// printBench scores the outcomes and prints them. A run that would have
// exited 4 makes the bench exit 4: its numbers are not all measured.
func printBench(e env, clients benchClients, cases []bench.Case, outcomes []bench.Outcome) int {
	res, err := benchResults(clients, cases, outcomes)
	if err != nil {
		printError(e.stderr, "creep bench", err)
		return exitcode.ConfigError
	}
	if err := writeBench(e.stdout, e.opts.format, res); err != nil {
		printError(e.stderr, "creep bench", err)
		return exitcode.ConfigError
	}
	for _, t := range res.Tiers {
		if t.IncompleteRuns > 0 {
			return exitcode.Incomplete
		}
	}
	return exitcode.OK
}

func benchResults(clients benchClients, cases []bench.Case, outcomes []bench.Outcome) (bench.Results, error) {
	tiers, err := bench.Score(cases, outcomes)
	if err != nil {
		return bench.Results{}, err
	}
	digest, err := bench.Digest()
	if err != nil {
		return bench.Results{}, err
	}
	return bench.Results{
		SchemaVersion: bench.SchemaVersion,
		Corpus:        bench.CorpusInfo{Cases: len(cases), SHA256: digest},
		Model:         bench.ModelInfo{Contract: clients.fixture.Contract, Name: clients.fixture.Name, Synthesized: clients.synthesized},
		Tiers:         tiers, Unmeasured: unmeasuredClasses(cases), Smoke: bench.SmokeRuns(),
	}, nil
}

// unmeasuredClasses are the coverage classes no case plants, in report
// order.
func unmeasuredClasses(cases []bench.Case) []string {
	out := []string{}
	for _, c := range classCoverage(coverageInput{}) {
		if !slices.ContainsFunc(cases, func(k bench.Case) bool { return k.Class == c.Class }) {
			out = append(out, c.Class)
		}
	}
	return out
}

func writeBench(w io.Writer, format string, res bench.Results) error {
	if format != "json" {
		_, err := io.WriteString(w, res.Markdown())
		return err
	}
	out, err := res.JSON()
	if err != nil {
		return err
	}
	_, err = w.Write(out)
	return err
}

// benchSeed is discovery's canary seed for every bench run. It is public
// and fixed, so the same corpus gives the same requests and the published
// fixture replays; a model could learn this canary, which is why only the
// bench uses it and a scan keeps its seed from crypto/rand.
var benchSeed = sha256.Sum256([]byte("creep bench discovery canary seed v1"))

// benchAll runs every case twin at every tier, in a fixed order.
func benchAll(ctx context.Context, m *models.HTTP, cases []bench.Case) ([]bench.Outcome, error) {
	var out []bench.Outcome
	for _, tier := range bench.Tiers() {
		for _, c := range cases {
			for _, v := range bench.Variants() {
				o, err := benchCase(ctx, m, calibrate.Tier(tier), c, v)
				if err != nil {
					return nil, fmt.Errorf("case %s %s tier %s: %w", c.ID, v, tier, err)
				}
				out = append(out, o)
			}
		}
	}
	return out, nil
}
