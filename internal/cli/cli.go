package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/sneakercreepers/creep/internal/exitcode"
)

// Run executes creep with args (without the program name) and returns the
// process exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	return runWith(args, stdout, stderr, productionDeps())
}

// runWith is Run with the scan's outside dependencies passed in, so tests
// drive every command through the same path with fakes.
func runWith(args []string, stdout, stderr io.Writer, deps scanDeps) int {
	out := &recordingWriter{w: stdout}
	return checkStdout(dispatch(args, out, stderr, deps), out, stderr)
}

// recordingWriter keeps the first write error, so no command or help path
// has to check every print to stdout itself.
type recordingWriter struct {
	w   io.Writer
	err error
}

func (r *recordingWriter) Write(p []byte) (int, error) {
	n, err := r.w.Write(p)
	if err != nil && r.err == nil {
		r.err = err
	}
	return n, err
}

// checkStdout turns a successful run whose stdout was lost (a full disk, a
// closed pipe on Windows) into exit 2, as config explain and a scan report
// already do, so nothing exits 0 with its output missing (#41). A failing
// code is kept: the run already reported why it failed.
func checkStdout(code int, out *recordingWriter, stderr io.Writer) int {
	if out.err == nil || code != exitcode.OK {
		return code
	}
	printError(stderr, "creep", fmt.Errorf("write stdout: %w", out.err))
	return exitcode.ConfigError
}

func dispatch(args []string, stdout, stderr io.Writer, deps scanDeps) int {
	opts := defaultOptions()
	fs := newFlagSet("creep", &opts)
	wantHelp, err := parseFlags(fs, args)
	if err != nil {
		return usageError("creep", err, stderr)
	}
	markExplicit(fs, &opts)
	if wantHelp {
		return runGlobalHelp(fs.Args(), opts, stdout, stderr)
	}
	rest := fs.Args()
	if len(rest) == 0 {
		return usageError("creep", errors.New("missing command"), stderr)
	}
	if rest[0] == "help" {
		return runHelp(rest[1:], opts, stdout, stderr)
	}
	cmd, ok := findCommand(rest[0])
	if !ok {
		return usageError("creep", fmt.Errorf("unknown command %q", rest[0]), stderr)
	}
	return runCommand(cmd, rest[1:], opts, env{stdout: stdout, stderr: stderr, deps: deps})
}

func runCommand(cmd command, args []string, opts globalOptions, e env) int {
	stdout, stderr := e.stdout, e.stderr
	positional, wantHelp, err := parseArgs("creep "+cmd.name, args, &opts)
	if err != nil {
		printError(stderr, "creep "+cmd.name, err)
		fmt.Fprintln(stderr)
		printCommandUsage(stderr, cmd)
		return exitcode.ConfigError
	}
	if invalidOptions(opts, stderr) {
		return exitcode.ConfigError
	}
	if wantHelp {
		printCommandUsage(stdout, cmd)
		return exitcode.OK
	}
	e.opts = opts
	return cmd.run(e, positional)
}

// runHelp handles "creep help [command]" with the same flag rules as any
// command, so invalid global flags fail here too instead of exiting 0.
func runHelp(args []string, opts globalOptions, stdout, stderr io.Writer) int {
	positional, _, err := parseArgs("creep help", args, &opts)
	if err != nil {
		return usageError("creep help", err, stderr)
	}
	if invalidOptions(opts, stderr) {
		return exitcode.ConfigError
	}
	switch len(positional) {
	case 0:
		printUsage(stdout)
		return exitcode.OK
	case 1:
		return printHelpFor(positional[0], stdout, stderr)
	default:
		return usageError("creep help", fmt.Errorf("unexpected arguments: %q", positional[1:]), stderr)
	}
}

// runGlobalHelp handles "creep -h ...". The flag package stops at the first
// positional, so the flags after it are parsed here: "creep -h version
// --format bad" must fail like "creep version -h --format bad" does.
func runGlobalHelp(rest []string, opts globalOptions, stdout, stderr io.Writer) int {
	if _, _, err := parseArgs("creep", rest, &opts); err != nil {
		return usageError("creep", err, stderr)
	}
	if invalidOptions(opts, stderr) {
		return exitcode.ConfigError
	}
	printUsage(stdout)
	return exitcode.OK
}

func printHelpFor(name string, stdout, stderr io.Writer) int {
	if name == "help" {
		printUsage(stdout)
		return exitcode.OK
	}
	cmd, ok := findCommand(name)
	if !ok {
		return usageError("creep help", fmt.Errorf("unknown command %q", name), stderr)
	}
	printCommandUsage(stdout, cmd)
	return exitcode.OK
}

// parseArgs parses flags found anywhere in a command's arguments and returns
// the positional ones.
func parseArgs(name string, args []string, opts *globalOptions) (positional []string, wantHelp bool, err error) {
	fs := newFlagSet(name, opts)
	flagArgs, positional := splitArgs(fs, args)
	wantHelp, err = parseFlags(fs, flagArgs)
	markExplicit(fs, opts)
	return positional, wantHelp, err
}

// parseFlags keeps parsing after -h/--help, which the flag package treats as
// a stop, so flags on either side of it are still validated.
func parseFlags(fs *flag.FlagSet, args []string) (wantHelp bool, err error) {
	for {
		err = fs.Parse(args)
		if !errors.Is(err, flag.ErrHelp) {
			return wantHelp, err
		}
		wantHelp = true
		args = fs.Args()
	}
}

// usageError reports a parse failure followed by the global usage.
func usageError(prefix string, err error, stderr io.Writer) int {
	printError(stderr, prefix, err)
	fmt.Fprintln(stderr)
	printUsage(stderr)
	return exitcode.ConfigError
}

// invalidOptions reports why the global flags are invalid, if they are.
func invalidOptions(opts globalOptions, stderr io.Writer) bool {
	err := opts.validate()
	if err != nil {
		printError(stderr, "creep", err)
	}
	return err != nil
}
