package verify

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/sneakercreepers/creep/internal/sandbox"
)

// testNonce is the nonce of every PoC the tests build.
const testNonce = "creep0123456789abcdef01234567"

const testPort = 8080

// app answers one raw request like an app under test would: a raw
// response, how long it took, and any marker table it created.
type app func(req string, tables map[string]bool) (string, time.Duration)

// fakeRunner stands in for the sandbox: it records every Exchange and
// answers each request with its app.
type fakeRunner struct {
	app    app
	tables map[string]bool
	ports  []int
	sent   [][][]byte
	looked []string
	err    error
}

func newFake(a app) *fakeRunner { return &fakeRunner{app: a, tables: map[string]bool{}} }

func (f *fakeRunner) Exchange(_ context.Context, port int, requests [][]byte) ([]sandbox.Exchange, error) {
	f.ports = append(f.ports, port)
	f.sent = append(f.sent, requests)
	if f.err != nil {
		return nil, f.err
	}
	out := make([]sandbox.Exchange, len(requests))
	for i, r := range requests {
		resp, elapsed := f.app(string(r), f.tables)
		out[i] = sandbox.Exchange{Response: []byte(resp), Elapsed: elapsed}
	}
	return out, nil
}

func (f *fakeRunner) DatabaseHasTable(_ context.Context, table string) (bool, error) {
	f.looked = append(f.looked, table)
	return f.tables[table], nil
}

// requests is every request the runner was sent, in order.
func (f *fakeRunner) requests() [][]byte {
	var all [][]byte
	for _, batch := range f.sent {
		all = append(all, batch...)
	}
	return all
}

func ok(body string) string { return "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n" + body }

func status(code string) string { return "HTTP/1.1 " + code + "\r\n\r\n" }

const fast = 100 * time.Millisecond

// loadRequest decodes a fixture strictly, as models.Complete would.
func loadRequest(t *testing.T, name string) Request {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "golden", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var r Request
	if err := dec.Decode(&r); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return r
}

func mustBuild(t *testing.T, r Request) PoC {
	t.Helper()
	p, err := build(r, testNonce)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	return p
}

// always answers every request with resp, at once.
func always(resp string) app {
	return func(string, map[string]bool) (string, time.Duration) { return resp, fast }
}

var createdTable = regexp.MustCompile(`CREATE(?:\+|%20| )TABLE(?:\+|%20| )(creep_[0-9a-f]+)`)
