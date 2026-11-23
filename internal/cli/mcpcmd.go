package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"strings"
	"sync"

	"github.com/sneakercreepers/creep/internal/buildinfo"
	"github.com/sneakercreepers/creep/internal/calibrate"
	"github.com/sneakercreepers/creep/internal/config"
	"github.com/sneakercreepers/creep/internal/exitcode"
	"github.com/sneakercreepers/creep/internal/mcp"
	"github.com/sneakercreepers/creep/internal/scanrun"
)

// maxMCPLogBytes bounds the scan log a tool reply carries.
const maxMCPLogBytes = 8 << 10

// runMCP serves the MCP tools over stdin and stdout until the host closes
// stdin (ADR 0027). Every scan it runs is a pull-request scan of the
// changed files the caller lists, with nothing that writes outside .creep/
// or starts a container: no sandbox, no PoC, no optional scanner, no
// consent prompt, no calibration run and no state key created.
func runMCP(e env, args []string) int {
	if len(args) > 0 {
		printError(e.stderr, "creep mcp", fmt.Errorf("takes no arguments; run it from the repository root (got %d)", len(args)))
		return exitcode.ConfigError
	}
	srv := &mcpServer{e: e}
	backend := mcp.Backend{Scan: srv.scan, LastReport: readLastReport, Version: buildinfo.Get().Version}
	if err := mcp.Serve(context.Background(), backend, e.deps.mcpInput(), nopWriteCloser{e.stdout}); err != nil {
		printError(e.stderr, "creep mcp", err)
		return exitcode.ConfigError
	}
	return exitcode.OK
}

// checkMCPFlags refuses the flags that would let an MCP scan verify
// findings in the sandbox or write outside .creep/: --mode nightly,
// --record (it rewrites recordings a later --replay trusts) and
// --recalibrate. runCommand checks it with the other per-command flags.
func checkMCPFlags(command string, o globalOptions) error {
	switch {
	case command != "mcp":
		return nil
	case o.explicit["mode"] && o.mode != string(config.ModePR):
		return errors.New("--mode: creep mcp scans only in pr mode; verification runs only from the CLI")
	case o.record:
		return errors.New("--record is not for creep mcp; record from the CLI")
	case o.recalibrate:
		return errors.New("--recalibrate is not for creep mcp; calibrate from the CLI")
	}
	return nil
}

type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }

// mcpInput is the protocol's input: stdin, or what a test passes.
func (d scanDeps) mcpInput() io.ReadCloser {
	if d.stdin != nil {
		return d.stdin
	}
	return os.Stdin
}

// mcpServer runs one scan at a time: the state lock refuses a second one
// anyway, and a caller looping on scan must not queue them.
type mcpServer struct {
	e  env
	mu sync.Mutex
}

func (m *mcpServer) scan(_ context.Context, changed []string) (mcp.ScanRun, error) {
	if !m.mu.TryLock() {
		return mcp.ScanRun{}, errors.New("a scan is already running")
	}
	defer m.mu.Unlock()
	list, err := parseChangedList([]byte(strings.Join(changed, "\x00")))
	if err != nil {
		return mcp.ScanRun{}, err
	}
	if err := requireStateKey(); err != nil {
		return mcp.ScanRun{}, err
	}
	var out, log cappedBuffer
	e := env{stdout: &out, stderr: &log, opts: mcpScanOptions(m.e.opts), deps: m.e.deps.forMCP(), changed: list}
	code := runScan(e, nil)
	return mcp.ScanRun{ExitCode: code, Log: log.String()}, nil
}

// mcpScanOptions are the server's options for one scan: pull-request mode
// and one sample, whatever the server was started with.
func mcpScanOptions(o globalOptions) globalOptions {
	o.explicit = maps.Clone(o.explicit)
	o.mode, o.stability, o.record, o.recalibrate, o.baselineWrite = string(config.ModePR), 1, false, false, false
	return o
}

// forMCP is d without anything that writes outside .creep/ or starts a
// container: no sandbox runtime, no optional scanner, no stability record,
// a cache-only calibration and a model link that never prompts.
func (d scanDeps) forMCP() scanDeps {
	d.sandbox = sandboxDeps{}
	d.recordStability = nil
	d.runScanner = func(context.Context, scanrun.Job) scanrun.Result { return scanrun.Result{Outcome: scanrun.NotRun} }
	if d.connectNoPrompt != nil {
		d.connect = d.connectNoPrompt
	}
	cal := d.calibrate
	d.calibrate = func(ctx context.Context, o calibrate.CacheOptions) (calibrate.Calibration, error) {
		o.CacheOnly, o.Recalibrate = true, false
		return cal(ctx, o)
	}
	return d
}

// requireStateKey refuses a scan before the state store would create the
// user's state key outside .creep/: a CLI scan creates it once.
func requireStateKey() error {
	key := userFile("state.key")
	if key == "" {
		return errors.New("no user config directory for the state key; run creep scan from the CLI first")
	}
	if _, err := os.Lstat(key); err != nil {
		return errors.New("no state key yet; run creep scan from the CLI once, then call scan again")
	}
	return nil
}

// cappedBuffer keeps the first maxMCPLogBytes written and drops the rest.
type cappedBuffer struct {
	b       strings.Builder
	dropped bool
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	room := maxMCPLogBytes - c.b.Len()
	if len(p) > room {
		c.b.Write(p[:max(room, 0)])
		c.dropped = true
		return len(p), nil
	}
	c.b.Write(p)
	return len(p), nil
}

func (c *cappedBuffer) String() string {
	if c.dropped {
		return c.b.String() + "\n[log cut]"
	}
	return c.b.String()
}
