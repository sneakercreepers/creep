package cli

import (
	"bytes"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/sneakercreepers/creep/internal/calibrate"
	"github.com/sneakercreepers/creep/internal/exitcode"
	"github.com/sneakercreepers/creep/internal/gateway/gatewaytest"
	"github.com/sneakercreepers/creep/internal/planner"
)

// plantedApp returns a Flask app whose injectable route holds secrets on
// the lines the reader slices (handler body and sink line), and the secret
// values. Values are built at run time, so this file holds none.
func plantedApp(rng *rand.Rand) (string, []string) {
	pick := func(alphabet string, n int) string {
		b := make([]byte, n)
		for i := range b {
			b[i] = alphabet[rng.IntN(len(alphabet))]
		}
		return string(b)
	}
	const alnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	secrets := []string{
		"AK" + "IA" + pick("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 16),
		pick(alnum, 24),
		"jane." + pick("abcdefghij", 8) + "@example.com",
		"gh" + "p_" + pick(alnum, 36),
		pick(alnum, 32),
		pick(alnum, 36), // not 40: the AWS secret-key detector would mask it anyway
	}
	// Subscript assignments (pentest P1): the Flask config idiom and a header.
	app := "from flask import Flask, request\nimport sqlite3\n\napp = Flask(__name__)\n" +
		fmt.Sprintf("app.config['SECRET_KEY'] = '%s'\n\n", secrets[4]) +
		"@app.get(\"/q\")\ndef q():\n" +
		fmt.Sprintf("    aws_key = %q\n    password = %q\n    owner = %q\n", secrets[0], secrets[1], secrets[2]) +
		"    headers = {}\n    name = request.args.get(\"name\", \"\")\n" +
		// Shares the sink line, so the reader's slice holds it.
		fmt.Sprintf("    headers['X-Api-Key'] = '%s'; return str(", secrets[5]) +
		"sqlite3.connect(\"x.db\").execute(\"SELECT * FROM t WHERE k = '" + secrets[3] +
		"' AND n = '\" + name + \"'\").fetchall())\n"
	return app, secrets
}

// endpointAnswer answers each discovery request with the canary only, and
// each reader request with verdict[class] (default not_vulnerable), from
// the HYPOTHESIS line only, never from code.
func endpointAnswer(verdict map[string]string) func([]byte) []byte {
	return func(body []byte) []byte {
		if answer, ok := discoveryAnswer(body, false); ok {
			reply, _ := chatReply(answer)
			return reply
		}
		m := hypothesisLine.FindSubmatch(body)
		if m == nil {
			return []byte(`{}`)
		}
		v := verdict[string(m[1])]
		if v == "" {
			v = "not_vulnerable"
		}
		sink, _ := strconv.Atoi(string(m[3]))
		reply, _ := chatReply(map[string]any{"verdict": v, "evidence": []map[string]int{{"start": sink, "end": sink}}, "confidence": 80})
		return reply
	}
}

// fixtureRun is one scan repository wired to a loopback model endpoint
// through the production gateway transport (connectGateway): consent from
// a policy file, egress.allow holding only the endpoint, real egress.log.
type fixtureRun struct {
	cfg      string
	endpoint *gatewaytest.Endpoint
	secrets  []string // planted in the repository and in CREEP_API_KEY
}

// newFixtureRun also allows and consents to extra endpoints, which only
// the broken runs of TestHolisticCatchesBrokenRun call.
func newFixtureRun(t *testing.T, seed uint64, verdict map[string]string, extra ...*gatewaytest.Endpoint) fixtureRun {
	t.Helper()
	app, secrets := plantedApp(rand.New(rand.NewPCG(seed, 17)))
	cfg := scanRepo(t, map[string]string{"app.py": app}, "")
	e := gatewaytest.New(t, endpointAnswer(verdict))
	hosts, origins := []string{e.Host()}, []string{e.URL()}
	for _, x := range extra {
		hosts, origins = append(hosts, x.Host()), append(origins, x.URL())
	}
	data := fmt.Sprintf("model:\n  contract: openai\n  endpoint: %s/v1\n  name: test-model\negress:\n  allow: ['%s']\n", e.URL(), strings.Join(hosts, "', '"))
	if err := os.WriteFile(cfg, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	policy := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(policy, []byte("consent: ['"+strings.Join(origins, "', '")+"']\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(policyEnv, policy)
	key := "sk-planted-" + fmt.Sprint(seed) + "-key-must-stay-in-the-header"
	t.Setenv("CREEP_API_KEY", key)
	return fixtureRun{cfg: cfg, endpoint: e, secrets: append(secrets, key)}
}

func productionTransport() scanDeps {
	return scanDeps{connect: connectGateway, calibrate: fixedCalibration(calibrate.TierM, nil)}
}

// Holistic fitness function (#17, from #138; invariants 2, 3 and 5 at
// once). A scan of a repository with planted secrets is recorded through
// the production gateway to a loopback endpoint, then replayed with
// --replay. Together: egress.log and every payload file hold no planted
// secret, every request the endpoint received is in egress.log, every
// logged call went to the replayed endpoint and the replay opened no
// connection, the planner input each run passed holds only IDs, enums,
// booleans and bounded numbers, and both runs exit with the code the
// exit-code table gives the verdict. TestHolisticCatchesBrokenRun shows each check failing.
func TestHolisticReplayProtections(t *testing.T) {
	tests := []struct {
		name     string
		verdict  map[string]string
		wantCode int
	}{
		{"gate exceeded", map[string]string{"sql_injection": "vulnerable"}, exitcode.GateExceeded},
		{"clean", nil, exitcode.OK},
		{"incomplete", map[string]string{"sql_injection": "inconclusive"}, exitcode.Incomplete},
	}
	seed := uint64(0)
	for _, tt := range tests {
		seed++
		t.Run(tt.name, func(t *testing.T) {
			run := newFixtureRun(t, seed, tt.verdict)
			var inputs []planner.Input
			deps := productionTransport()
			deps.planned = func(in planner.Input) { inputs = append(inputs, in) }
			code, recorded, errOut := runScanWith(deps, "scan", "--record", "--config", run.cfg)
			if code != tt.wantCode {
				t.Fatalf("record: exit %d, want %d\n%s\n%s", code, tt.wantCode, recorded, errOut)
			}
			conns, bodies := run.endpoint.Conns(), run.endpoint.Bodies()
			if conns == 0 || !sentMaskedSink(bodies) {
				t.Fatalf("record reached the endpoint over %d connections without the masked sink line; the check would be vacuous\n%s", conns, bodies)
			}
			code, replayed, errOut := runScanWith(deps, "scan", "--replay", "--config", run.cfg)
			if code != tt.wantCode || replayed != recorded {
				t.Fatalf("replay: exit %d, want %d\nrecorded:\n%s\nreplayed:\n%s\n%s", code, tt.wantCode, recorded, replayed, errOut)
			}
			problems := replayConns(conns, run.endpoint.Conns())
			problems = append(problems, runProblems(t, run.secrets, run.endpoint.URL()+"/v1/", run.endpoint.Bodies())...)
			problems = append(problems, plannedText(inputs)...)
			if len(problems) != 0 {
				t.Fatalf("protections broken:\n%s", strings.Join(problems, "\n"))
			}
		})
	}
}

// plannedText walks the planner input of each run, record then replay. A
// run that planned nothing, or no sink, would make the walk vacuous.
func plannedText(inputs []planner.Input) []string {
	if len(inputs) != 2 {
		return []string{fmt.Sprintf("planner saw %d inputs, want one per run", len(inputs))}
	}
	var out []string
	for i, in := range inputs {
		if len(in.Sinks) == 0 {
			out = append(out, fmt.Sprintf("planner input %d has no sink; the text check would be vacuous", i))
		}
		out = append(out, valueText(in, "planner.Input")...)
	}
	return out
}

// sentMaskedSink is true when a reader request carried the sink line with
// its secret masked, and the subscript-assigned header (pentest P1), so the
// leak checks look at real slices.
func sentMaskedSink(bodies [][]byte) bool {
	for _, b := range bodies {
		if bytes.Contains(b, []byte("SELECT * FROM t WHERE k = ")) && bytes.Contains(b, []byte("SECRET_")) &&
			bytes.Contains(b, []byte("headers['X-Api-Key'] = '")) {
			return true
		}
	}
	return false
}

// replayConns reports connections the endpoint accepted during a replay.
func replayConns(before, after int) []string {
	if after == before {
		return nil
	}
	return []string{fmt.Sprintf("replay opened %d connections, want none", after-before)}
}
