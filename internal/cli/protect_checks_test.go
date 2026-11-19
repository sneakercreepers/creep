package cli

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/sneakercreepers/creep/internal/calibrate"
	"github.com/sneakercreepers/creep/internal/config"
	"github.com/sneakercreepers/creep/internal/gateway"
	"github.com/sneakercreepers/creep/internal/gateway/gatewaytest"
	"github.com/sneakercreepers/creep/internal/planner"
)

// runProblems checks every run under .creep/runs: no planted secret in
// egress.log or a payload file, every logged call addressed to endpoint,
// and every body the endpoint received logged with its SHA-256.
func runProblems(t *testing.T, secrets []string, endpoint string, bodies [][]byte) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(stateDir, "runs", "*", "egress.log"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no egress.log under %s: %v", stateDir, err)
	}
	payloads, err := filepath.Glob(filepath.Join(stateDir, "runs", "*", "payloads", "*"))
	if err != nil {
		t.Fatal(err)
	}
	var problems []string
	logged := map[string]bool{}
	for _, name := range append(files, payloads...) {
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range secrets {
			if bytes.Contains(data, []byte(s)) {
				problems = append(problems, fmt.Sprintf("planted secret %.12q... in %s", s, filepath.Base(name)))
			}
		}
		if filepath.Base(name) == "egress.log" {
			problems = append(problems, requestLines(t, data, endpoint, logged)...)
		}
	}
	for _, b := range bodies {
		sum := sha256.Sum256(b)
		if !logged[hex.EncodeToString(sum[:])] {
			problems = append(problems, fmt.Sprintf("%d-byte request reached the endpoint without an egress.log line", len(b)))
		}
	}
	return problems
}

// requestLines adds each request line's hash to logged and reports a call
// addressed anywhere but endpoint.
func requestLines(t *testing.T, log []byte, endpoint string, logged map[string]bool) []string {
	t.Helper()
	var problems []string
	sc := bufio.NewScanner(bytes.NewReader(log))
	for sc.Scan() {
		var line struct{ Type, Endpoint, SHA256 string }
		if err := json.Unmarshal(sc.Bytes(), &line); err != nil {
			t.Fatalf("egress.log line %q: %v", sc.Text(), err)
		}
		if line.Type != "request" {
			continue
		}
		logged[line.SHA256] = true
		if !strings.HasPrefix(line.Endpoint, endpoint) {
			problems = append(problems, fmt.Sprintf("call to %s, not the replayed endpoint", line.Endpoint))
		}
	}
	return problems
}

// valueText reports every value reachable from v that can carry text:
// strings, byte or rune sequences, maps, interfaces, funcs, chans, floats.
// It walks the value the planner gets, where planner/text_test.go walks
// its type.
func valueText(v any, path string) []string {
	return walkText(reflect.ValueOf(v), path)
}

func walkText(v reflect.Value, path string) []string {
	switch v.Kind() {
	case reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return nil
	case reflect.Pointer:
		if v.IsNil() {
			return nil
		}
		return walkText(v.Elem(), path+"*")
	case reflect.Slice, reflect.Array:
		if v.Type().Elem().Kind() != reflect.Struct {
			return []string{path + " holds " + v.Type().String()}
		}
		var out []string
		for i := range v.Len() {
			out = append(out, walkText(v.Index(i), fmt.Sprintf("%s[%d]", path, i))...)
		}
		return out
	case reflect.Struct:
		var out []string
		for i := range v.NumField() {
			out = append(out, walkText(v.Field(i), path+"."+v.Type().Field(i).Name)...)
		}
		return out
	}
	return []string{path + " holds " + v.Kind().String()}
}

// repoPlannerInput builds the planner input from the repository in the
// current directory exactly as scan does (walkRepo, discovery with a model
// that reports the canary, plannerInput).
func repoPlannerInput(t *testing.T) planner.Input {
	t.Helper()
	rs := discoverHere(t, &fakeModel{}, calibrate.TierM)
	ptier, err := plannerTier(calibrate.TierM)
	if err != nil {
		t.Fatal(err)
	}
	in, _ := plannerInput(rs.res, ptier, planner.Budget{})
	if len(in.Sinks) == 0 {
		t.Fatal("fixture has no sink; the planner check would be vacuous")
	}
	return in
}

// sendBreaking wraps the production transport so each call is altered
// before the gateway sees it: a deliberately broken run, test only.
func sendBreaking(alter func(*gateway.Call)) scanDeps {
	deps := productionTransport()
	deps.connect = func(r *config.Resolved, dir string, stderr io.Writer) (modelLink, error) {
		link, err := connectGateway(r, dir, stderr)
		if err != nil {
			return link, err
		}
		send := link.send
		link.send = func(ctx context.Context, c gateway.Call) (*gateway.Reply, error) {
			alter(&c)
			return send(ctx, c)
		}
		return link, nil
	}
	return deps
}

// Each check of TestHolisticReplayProtections must fail on a run broken
// on purpose, so the holistic test cannot pass vacuously.
func TestHolisticCatchesBrokenRun(t *testing.T) {
	tests := []struct {
		name  string
		check func(t *testing.T, run fixtureRun, other *gatewaytest.Endpoint) []string
		want  string
	}{
		{"secret appended to a payload", func(t *testing.T, run fixtureRun, _ *gatewaytest.Endpoint) []string {
			runScanWith(sendBreaking(func(c *gateway.Call) { c.Payload = append(c.Payload, run.secrets[0]...) }), "scan", "--record", "--config", run.cfg)
			return runProblems(t, run.secrets, run.endpoint.URL()+"/v1/", run.endpoint.Bodies())
		}, "planted secret"},
		{"call to a second endpoint", func(t *testing.T, run fixtureRun, other *gatewaytest.Endpoint) []string {
			_, out, errOut := runScanWith(sendBreaking(func(c *gateway.Call) { c.Endpoint = other.URL() + "/v1/chat/completions" }), "scan", "--record", "--config", run.cfg)
			if other.Conns() == 0 {
				t.Fatalf("the broken run never reached the second endpoint\n%s\n%s", out, errOut)
			}
			return runProblems(t, run.secrets, run.endpoint.URL()+"/v1/", run.endpoint.Bodies())
		}, "not the replayed endpoint"},
		{"request the endpoint got outside egress.log", func(t *testing.T, run fixtureRun, _ *gatewaytest.Endpoint) []string {
			runScanWith(productionTransport(), "scan", "--record", "--config", run.cfg)
			return runProblems(t, run.secrets, run.endpoint.URL()+"/v1/", append(run.endpoint.Bodies(), []byte("unlogged")))
		}, "without an egress.log line"},
		{"second run live instead of replayed", func(t *testing.T, run fixtureRun, _ *gatewaytest.Endpoint) []string {
			runScanWith(productionTransport(), "scan", "--record", "--config", run.cfg)
			before := run.endpoint.Conns()
			runScanWith(productionTransport(), "scan", "--record", "--config", run.cfg)
			return replayConns(before, run.endpoint.Conns())
		}, "replay opened"},
		{"planner input with a text field", func(t *testing.T, _ fixtureRun, _ *gatewaytest.Endpoint) []string {
			return valueText(struct {
				In   planner.Input
				Note string
			}{repoPlannerInput(t), "x"}, "input")
		}, "input.Note holds string"},
	}
	seed := uint64(100)
	for _, tt := range tests {
		seed++
		t.Run(tt.name, func(t *testing.T) {
			other := gatewaytest.New(t, endpointAnswer(nil))
			run := newFixtureRun(t, seed, nil, other)
			got := strings.Join(tt.check(t, run, other), "\n")
			if !strings.Contains(got, tt.want) {
				t.Fatalf("problems:\n%s\nwant one containing %q", got, tt.want)
			}
		})
	}
}
