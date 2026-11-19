package cli

import (
	"fmt"
	"os"

	"github.com/sneakercreepers/creep/internal/exitcode"
	"github.com/sneakercreepers/creep/internal/state"
)

// stateDir is the run-state directory, relative to the scanned project.
const stateDir = ".creep"

// runResume checks that the run can be resumed, then fails closed:
// continuing a run from its recorded steps is not built, and a resume that
// exits 0 having scanned nothing must not pass a CI gate.
func runResume(e env, args []string) int {
	if len(args) != 1 {
		printError(e.stderr, "creep resume", fmt.Errorf("want exactly one run ID, got %d arguments", len(args)))
		return exitcode.ConfigError
	}
	sum, err := loadResumable(args[0])
	if err != nil {
		printError(e.stderr, "creep resume", err)
		return exitcode.ConfigError
	}
	fmt.Fprintf(e.stderr, "creep resume: run %s (%s) has %d completed steps; continuing a run is not implemented yet, so start a new one with creep scan\n",
		sum.ID, sum.Mode, len(sum.Steps))
	return exitcode.ConfigError
}

// loadResumable reopens the run under the state lock, so a scan still
// writing to it fails the resume (state.ErrLocked) instead of reading a log
// mid-append, and refuses a run that already ended. It appends nothing and
// never creates the state directory: resuming in the wrong folder must not
// leave one behind.
func loadResumable(id string) (state.Summary, error) {
	if _, err := os.Lstat(stateDir); err != nil {
		return state.Summary{}, fmt.Errorf("no run state in this directory: %w", err)
	}
	store, err := state.OpenUser(stateDir)
	if err != nil {
		return state.Summary{}, err
	}
	defer store.Close()
	run, err := store.Resume(id)
	if err != nil {
		return state.Summary{}, err
	}
	defer run.Close()
	return run.Summary(), nil
}
