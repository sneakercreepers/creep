package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/sneakercreepers/creep/internal/exitcode"
)

func printUsage(w io.Writer) {
	var b strings.Builder
	b.WriteString("creep finds vulnerabilities in local source code.\n\n")
	b.WriteString("Usage:\n  creep [global flags] <command> [flags] [args]\n\n")
	b.WriteString("Commands:\n")
	for _, c := range commands {
		fmt.Fprintf(&b, "  %-8s %s\n", c.name, c.summary)
	}
	fmt.Fprintf(&b, "  %-8s %s\n\n", "help", "show this help")
	b.WriteString(globalFlagsHelp())
	b.WriteString("\n")
	b.WriteString(exitcode.Help())
	fmt.Fprint(w, b.String())
}

func printCommandUsage(w io.Writer, c command) {
	fmt.Fprintf(w, "Usage:\n  creep %s [flags]\n\n%s.\n\n%s\n%s", c.name, c.summary, globalFlagsHelp(), exitcode.Help())
}

func globalFlagsHelp() string {
	d := defaultOptions()
	return fmt.Sprintf("Global flags (before or after the command; \"--\" ends flags):\n"+
		"  --config <path>     config file used instead of the user and project files\n"+
		"  --model-run <cmd>   model CLI for contract command: prompt on stdin, JSON out\n"+
		"  --mode <mode>       scan: pr or nightly, which gate judges it (default pr, nightly\n"+
		"                      on a GitHub Actions schedule event); only nightly verifies\n"+
		"  --format <format>   output format: %s (default %q)\n"+
		"  --log-level <level> log level: %s (default %q)\n"+
		"  --record            call every model and record the responses for replay\n"+
		"  --replay            serve recorded responses only; never use the network\n"+
		"  --recalibrate       calibrate the model again even if a calibration is cached\n"+
		"  --stats             scan: print phase times, model calls, cache hits and tokens\n"+
		"  --changed <file>    scan, estimate: only the paths listed in file, one per line or\n"+
		"                      NUL-separated (git diff --name-only -z origin/main > changed.txt);\n"+
		"                      every other source file is listed unchanged and not evaluated\n"+
		"  --price-in <n>      estimate, --stats: price per 1M input tokens, for a cost\n"+
		"  --price-out <n>     estimate, --stats: price per 1M output tokens, for a cost\n"+
		"  --baseline <file>   scan: do not gate on findings the file's live entries match\n"+
		"                      (each still listed); accept: the file to write (default\n"+
		"                      "+defaultBaselineFile+")\n"+
		"  --baseline-write    scan: rewrite --baseline from this run's findings (a complete\n"+
		"                      run only); accepted risks are kept\n"+
		"  --expires <n>d      accept: days until the accepted risk expires (1d to 365d)\n"+
		"  --reason <text>     accept: why the risk is accepted (required)\n",
		strings.Join(formats, ", "), d.format, strings.Join(logLevels, ", "), d.logLevel)
}
