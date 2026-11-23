package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/sneakercreepers/creep/internal/config"
	"github.com/sneakercreepers/creep/internal/exitcode"
	"github.com/sneakercreepers/creep/internal/report"
	"github.com/sneakercreepers/creep/internal/sandbox"
	"github.com/sneakercreepers/creep/internal/verify"
)

// runReproduce runs the PoC of one verified finding of the last scan
// again, from its bundle in .creep/bundles, against an app built afresh
// from the repository in the current directory (#25). It needs no model:
// it reads no model setting, opens no model link and makes no network
// call; only the sandbox runs, offline as in a scan. It exits 0 when the
// PoC verified in at least one run, 1 when it verified in none, 2 for
// usage, configuration or a missing or refused bundle, 3 when the sandbox
// could not build or start the app.
func runReproduce(e env, args []string) int {
	if len(args) != 1 {
		printError(e.stderr, "creep reproduce", fmt.Errorf("want exactly one finding ID, got %d arguments", len(args)))
		return exitcode.ConfigError
	}
	resolved, err := loadConfig(e.opts)
	if err != nil {
		printError(e.stderr, "creep reproduce", err)
		return exitcode.ConfigError
	}
	if !resolved.Config.Sandbox.Enabled {
		printError(e.stderr, "creep reproduce", errors.New("needs sandbox.enabled: true (user config, --config or CREEP_POLICY), since it builds and runs the app"))
		return exitcode.ConfigError
	}
	b, p, err := loadBundle(args[0])
	if err != nil {
		printError(e.stderr, "creep reproduce", err)
		return exitcode.ConfigError
	}
	return reproduce(e, resolved.Config, b, p)
}

// loadBundle reads the finding's bundle and rebuilds its PoC through
// Build, so a bundle is never trusted more than the model's own output.
func loadBundle(id string) (verify.Bundle, verify.PoC, error) {
	b, err := readBundle(id)
	if err != nil {
		return verify.Bundle{}, verify.PoC{}, err
	}
	p, err := verify.Build(b.PoC)
	if err != nil {
		return verify.Bundle{}, verify.PoC{}, fmt.Errorf("bundle %s: %w", id, err)
	}
	if !verify.Fits(b.Class, p) {
		return verify.Bundle{}, verify.PoC{}, fmt.Errorf("bundle %s: template %s does not prove %s: %w", id, p.Template(), b.Class, verify.ErrBundle)
	}
	return b, p, nil
}

// reproduce builds the app in a fresh sandbox, closed on every path, and
// runs the PoC as many times as the scan did, by budget.max_seconds.
func reproduce(e env, cfg config.Config, b verify.Bundle, p verify.PoC) int {
	rep, checked := detectSandbox(context.Background(), e.deps.sandbox, cfg.Sandbox)
	best, ok := rep.Best()
	if !checked || !ok || e.deps.sandbox.open == nil {
		printError(e.stderr, "creep reproduce", errors.New("no usable docker or podman (see creep doctor)"))
		return exitcode.ModelOrSandbox
	}
	repo, err := os.OpenRoot(".")
	if err != nil {
		printError(e.stderr, "creep reproduce", err)
		return exitcode.ConfigError
	}
	defer repo.Close()
	ctx, stop := e.deps.sandbox.interruptible(context.Background())
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, time.Duration(cfg.Budget.MaxSeconds)*time.Second)
	defer cancel()
	files, err := walkRepo(ctx, repo)
	if err != nil {
		printError(e.stderr, "creep reproduce", err)
		return exitcode.ConfigError
	}
	box, err := e.deps.sandbox.open(best, reproduceRunID(), buildMirror(cfg.Sandbox))
	if err != nil {
		printError(e.stderr, "creep reproduce: sandbox", err)
		return exitcode.ModelOrSandbox
	}
	defer closeSandbox(e.stderr, box)
	return runBundle(ctx, e, box, repo, files.paths, b, p)
}

func runBundle(ctx context.Context, e env, box appSandbox, repo *os.Root, paths []string, b verify.Bundle, p verify.PoC) int {
	printBundle(e.stdout, b, headCommit(repo))
	app, err := box.Build(ctx, sandbox.Repo{Paths: paths, Read: buildReader(repo)})
	if v := appVerification(ctx, app, err); v.Status != report.VerificationAppBuilt {
		fmt.Fprintf(e.stderr, "creep reproduce: %s\n", v.Text())
		return exitcode.ModelOrSandbox
	}
	t, failed := startTarget(ctx, e.stderr, box, app, repo, paths)
	if failed != nil {
		fmt.Fprintf(e.stderr, "creep reproduce: %s\n", failed.Text())
		return exitcode.ModelOrSandbox
	}
	got, err := verify.Repeat(ctx, box, t.target, p, b.Rate.Runs)
	if err != nil {
		printError(e.stderr, "creep reproduce: sandbox", err)
		return exitcode.ModelOrSandbox
	}
	return printReproduced(e.stdout, b, got)
}

// printBundle says what is being reproduced. Every value is an ID, a
// number or a hash the bundle check accepted.
func printBundle(w io.Writer, b verify.Bundle, head string) {
	fmt.Fprintf(w, "reproduce %s: %s with %s, %d runs; the scan verified it in %s\n", b.Finding, b.Class, b.PoC.Template, b.Rate.Runs, b.Rate)
	switch {
	case b.Commit == "" || head == "":
		fmt.Fprintln(w, "commit: unknown; the app is built from the working tree as it is now")
	case b.Commit != head:
		fmt.Fprintf(w, "commit: the bundle is from %s, HEAD is %s; the app is built from the working tree as it is now\n", b.Commit, head)
	default:
		fmt.Fprintf(w, "commit: %s\n", head)
	}
}

func printReproduced(w io.Writer, b verify.Bundle, got verify.Repetition) int {
	for i, res := range got.Results {
		fmt.Fprintf(w, "  run %d: %s (%s)\n", i+1, res.Outcome, res.Oracle)
	}
	if !got.Rate.Holds() {
		fmt.Fprintf(w, "not reproduced: verified in %s runs (the scan: %s)\n", got.Rate, b.Rate)
		return exitcode.GateExceeded
	}
	text := report.PoCRate{Verified: got.Rate.Verified, Runs: got.Rate.Runs}.Text()
	fmt.Fprintf(w, "reproduced: %s (the scan: %s)\n", text, b.Rate)
	return exitcode.OK
}

// reproduceRunID labels the sandbox's containers and network; a fresh
// one per call, so creep clean and Close find exactly this run's.
func reproduceRunID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return "reproduce-" + hex.EncodeToString(b[:])
}
