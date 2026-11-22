package cli

import (
	"errors"
	"fmt"
	"path"

	"github.com/sneakercreepers/creep/internal/baseline"
	"github.com/sneakercreepers/creep/internal/exitcode"
	"github.com/sneakercreepers/creep/internal/report"
)

// runAccept records a finding of the last scan as an accepted risk in the
// baseline file: `creep accept <id> --expires 90d --reason "..."`. Both
// flags are required; the finding must be probable or verified. The entry
// suppresses the finding only in a scan given that file with --baseline,
// and only until it expires (ADR 0022).
func runAccept(e env, args []string) int {
	if err := acceptFinding(e, args); err != nil {
		printError(e.stderr, "creep accept", err)
		return exitcode.ConfigError
	}
	return exitcode.OK
}

func acceptFinding(e env, args []string) error {
	days, err := acceptArgs(e.opts, args)
	if err != nil {
		return err
	}
	f, err := lastFinding(args[0])
	if err != nil {
		return err
	}
	file := e.opts.baseline
	if file == "" {
		file = defaultBaselineFile
	}
	today := e.deps.today()
	old, err := readBaselineFile(file, today, true)
	if err != nil {
		return err
	}
	b, err := baseline.Accept(old, f, days, e.opts.reason, today)
	if err == nil {
		err = writeBaselineFile(file, b)
	}
	if err != nil {
		return err
	}
	expires := b.Entries[len(b.Entries)-1].Expires
	fmt.Fprintf(e.stdout, "accepted %s (%s, %s) until %s in %s; scan with --baseline %s to apply it\n",
		f.ID, f.Class, escapeControl(location(f)), expires, escapeControl(file), escapeControl(file))
	return nil
}

// acceptArgs checks the ID and both required flags and returns the expiry
// in days, before any file is read.
func acceptArgs(o globalOptions, args []string) (int, error) {
	if len(args) != 1 || !report.ValidID(args[0]) {
		return 0, errors.New("want exactly one valid finding ID, from the last scan's report")
	}
	if !o.explicit["expires"] || !o.explicit["reason"] {
		return 0, errors.New("an accepted risk needs --expires <days>d and --reason <text>")
	}
	return baseline.ParseDays(o.expires)
}

// lastFinding is the finding id of the last scan's JSON report.
func lastFinding(id string) (report.Finding, error) {
	rep, err := readLastReport()
	if err != nil {
		return report.Finding{}, err
	}
	f, ok := rep.Finding(id)
	if !ok {
		return report.Finding{}, fmt.Errorf("no finding %s in %s", id, path.Join(stateDir, reportNames["json"]))
	}
	return f, nil
}
