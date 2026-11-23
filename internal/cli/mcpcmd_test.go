package cli

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sneakercreepers/creep/internal/exitcode"
)

// mcpClient drives creep mcp over pipes with raw JSON-RPC lines: internal/cli
// may not import the SDK (only internal/mcp may, ADR 0027).
type mcpClient struct {
	t      *testing.T
	in     *io.PipeWriter
	out    *bufio.Reader
	nextID int
	done   chan int
	stderr *bytes.Buffer
}

// startMCP runs creep mcp with deps and args and completes the handshake.
func startMCP(t *testing.T, deps scanDeps, args ...string) *mcpClient {
	t.Helper()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	deps.stdin = inR
	c := &mcpClient{t: t, in: inW, out: bufio.NewReader(outR), done: make(chan int, 1), stderr: &bytes.Buffer{}}
	go func() {
		code := runWith(append(args, "mcp"), outW, c.stderr, deps)
		_ = outW.Close()
		c.done <- code
	}()
	c.request("initialize", map[string]any{
		"protocolVersion": "2025-06-18", "capabilities": map[string]any{},
		"clientInfo": map[string]any{"name": "test", "version": "0"},
	})
	c.send(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})
	return c
}

func (c *mcpClient) send(msg map[string]any) {
	c.t.Helper()
	line, err := json.Marshal(msg)
	if err != nil {
		c.t.Fatal(err)
	}
	if _, err := c.in.Write(append(line, '\n')); err != nil {
		c.t.Fatalf("write to creep mcp: %v (stderr %s)", err, c.stderr)
	}
}

// request sends one call and returns its result, skipping notifications.
func (c *mcpClient) request(method string, params any) json.RawMessage {
	c.t.Helper()
	c.nextID++
	c.send(map[string]any{"jsonrpc": "2.0", "id": c.nextID, "method": method, "params": params})
	for {
		line, err := c.out.ReadBytes('\n')
		if err != nil {
			c.t.Fatalf("read from creep mcp: %v (stderr %s)", err, c.stderr)
		}
		var reply struct {
			ID     *int            `json:"id"`
			Result json.RawMessage `json:"result"`
			Error  json.RawMessage `json:"error"`
		}
		if err := json.Unmarshal(line, &reply); err != nil {
			c.t.Fatalf("creep mcp wrote a line that is not JSON-RPC: %q", line)
		}
		if reply.ID == nil || *reply.ID != c.nextID {
			continue
		}
		if reply.Error != nil {
			c.t.Fatalf("%s: protocol error %s", method, reply.Error)
		}
		return reply.Result
	}
}

// tool calls one tool and returns its text and whether it is a tool error.
func (c *mcpClient) tool(name string, args any) (string, bool) {
	c.t.Helper()
	var res struct {
		Content []struct{ Text string } `json:"content"`
		IsError bool                    `json:"isError"`
	}
	if err := json.Unmarshal(c.request("tools/call", map[string]any{"name": name, "arguments": args}), &res); err != nil {
		c.t.Fatal(err)
	}
	var b strings.Builder
	for _, part := range res.Content {
		b.WriteString(part.Text)
	}
	return b.String(), res.IsError
}

// stop closes stdin, which ends the server, and returns its exit code.
func (c *mcpClient) stop() int {
	c.t.Helper()
	_ = c.in.Close()
	go func() { _, _ = io.Copy(io.Discard, c.out) }()
	select {
	case code := <-c.done:
		return code
	case <-time.After(30 * time.Second):
		c.t.Fatal("creep mcp did not stop when stdin closed")
		return -1
	}
}

// treeState is every file and directory under the roots with its size,
// mode and content hash, so any write, removal or new file shows.
func treeState(t *testing.T, roots ...string) map[string]string {
	t.Helper()
	state := map[string]string{}
	for _, root := range roots {
		err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			info, err := d.Info()
			if err != nil {
				return err
			}
			entry := info.Mode().String()
			if info.Mode().IsRegular() {
				data, err := os.ReadFile(p) //nolint:gosec // G304: p is under the test's own temporary roots
				if err != nil {
					return err
				}
				entry += " " + string(data)
			}
			state[p] = entry
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return state
}

// changedOutside lists the paths that differ between two tree states and
// are not under allowed; "" allows none.
func changedOutside(before, after map[string]string, allowed string) []string {
	var changed []string
	for p, v := range after {
		if before[p] != v && !underDir(p, allowed) {
			changed = append(changed, p)
		}
	}
	for p := range before {
		if _, ok := after[p]; !ok && !underDir(p, allowed) {
			changed = append(changed, p)
		}
	}
	return changed
}

func underDir(p, dir string) bool {
	return dir != "" && (p == dir || strings.HasPrefix(p, dir+string(filepath.Separator)))
}

func TestMCPRefusesUnsafeFlags(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"nightly mode", []string{"--mode", "nightly", "mcp"}, "pr mode"},
		{"record", []string{"--record", "mcp"}, "--record"},
		{"recalibrate", []string{"--recalibrate", "mcp"}, "--recalibrate"},
		{"stability", []string{"--stability", "3", "mcp"}, "--stability"},
		{"changed file", []string{"--changed", "list.txt", "mcp"}, "--changed"},
		{"baseline", []string{"--baseline", "b.json", "mcp"}, "--baseline"},
		{"baseline write", []string{"--baseline", "b.json", "--baseline-write", "mcp"}, "--baseline"},
		{"argument", []string{"mcp", "."}, "takes no arguments"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, stdout, stderr := runScanWith(noModelDeps, tt.args...)
			if code != exitcode.ConfigError || stdout != "" || !strings.Contains(stderr, tt.want) {
				t.Errorf("exit %d, stdout %q, stderr %q; want exit 2 naming %s", code, stdout, stderr, tt.want)
			}
		})
	}
}

func TestMCPProductionNeverPrompts(t *testing.T) {
	if productionDeps().connectNoPrompt == nil {
		t.Fatal("production creep mcp would connect through the consent prompt, which reads stdin")
	}
}
