package cli

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sneakercreepers/creep/internal/calibrate"
	"github.com/sneakercreepers/creep/internal/config"
	"github.com/sneakercreepers/creep/internal/exitcode"
	"github.com/sneakercreepers/creep/internal/gateway"
)

// cancelMethod is the MCP notification that calls off a request.
const cancelMethod = "notifications/cancelled" //nolint:misspell // the protocol's spelling

// A scan call the agent calls off stops the scan's model calls: an agent
// that gives up on a scan must not leave it spending the operator's
// budget, holding the one-scan lock until the deadline (ADR 0027, MC6).
func TestMCPCancelStopsScan(t *testing.T) {
	_, cfg, _ := mcpRepo(t, map[string]string{"app.py": "@flask"}, "")
	deps := fakeDeps(&fakeModel{verdict: sqliVulnerable}, calibrate.TierM)
	if code, out, errOut := runScanWith(deps, "--config", cfg, "scan"); code != exitcode.GateExceeded {
		t.Fatalf("CLI scan: exit %d\n%s%s", code, out, errOut)
	}
	// A changed file misses the CLI scan's recordings, so the model is called.
	appendFile(t, "app.py", "\n# changed\n")

	started, stopped := make(chan struct{}), make(chan bool, 1)
	calls := 0
	deps.connect = func(*config.Resolved, string, io.Writer) (modelLink, error) {
		send := func(ctx context.Context, _ gateway.Call) (*gateway.Reply, error) {
			calls++
			if calls == 1 {
				close(started)
			}
			select {
			case <-ctx.Done():
				stopped <- true
				return nil, ctx.Err()
			case <-time.After(10 * time.Second):
				stopped <- false
				return nil, context.DeadlineExceeded
			}
		}
		return modelLink{send: send, close: func() error { return nil }}, nil
	}

	c := startMCP(t, deps, "--config", cfg)
	c.send(map[string]any{"jsonrpc": "2.0", "id": 7, "method": "tools/call",
		"params": map[string]any{"name": "scan", "arguments": map[string]any{"changed": []string{"app.py"}}}})
	<-started
	cancel, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "method": cancelMethod, "params": map[string]any{"requestId": 7}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.in.Write(append(cancel, '\n')); err != nil {
		t.Fatal(err)
	}
	if !<-stopped {
		t.Fatal("the called-off scan's model call never saw its context end")
	}
	if code := c.stop(); code != exitcode.OK {
		t.Fatalf("creep mcp exit %d: %s", code, c.stderr)
	}
	if calls != 1 {
		t.Errorf("the scan made %d model calls; want none after the cancel", calls)
	}
}

func appendFile(t *testing.T, name, text string) {
	t.Helper()
	f, err := os.OpenFile(filepath.Clean(name), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(text); err != nil {
		t.Fatal(err)
	}
}
