package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/sneakercreepers/creep/internal/calibrate"
	"github.com/sneakercreepers/creep/internal/config"
	"github.com/sneakercreepers/creep/internal/exitcode"
	"github.com/sneakercreepers/creep/internal/gateway"
	"github.com/sneakercreepers/creep/internal/models"
	"github.com/sneakercreepers/creep/internal/report"
)

// offlineDeps fails the test if estimate asks for a transport, and
// proves the model it hands calibration cannot send: the fake makes one
// request through it and requires errNoModelCall. cached decides whether
// the calibration is found in the cache.
func offlineDeps(t *testing.T, cached bool) scanDeps {
	t.Helper()
	return scanDeps{
		connect: func(*config.Resolved, string, io.Writer) (modelLink, error) {
			t.Error("estimate asked for a model transport")
			return modelLink{}, errors.New("no transport in estimate")
		},
		calibrate: func(ctx context.Context, opts calibrate.CacheOptions) (calibrate.Calibration, error) {
			_, err := models.Complete[calibrateProbe](ctx, opts.Model, models.Request{Purpose: "probe", Prompt: "x", Schema: []byte(`{"type":"object"}`)})
			if !errors.Is(err, errNoModelCall) {
				t.Errorf("calibration model sent a request: %v", err)
			}
			if !cached {
				return calibrate.Calibration{}, err
			}
			return fixedCalibration(calibrate.TierM, nil)(ctx, opts)
		},
	}
}

type calibrateProbe struct{}

func (calibrateProbe) Validate() error { return nil }

// Acceptance (#15): estimate makes no network or model calls, never
// creates .creep, and prints a row per tier, with or without a cached
// calibration and on an empty repository.
func TestEstimateMakesNoModelCalls(t *testing.T) {
	tests := []struct {
		name   string
		files  map[string]string
		cached bool
		want   []string
	}{
		{"cached calibration", map[string]string{"app.py": "@flask"}, true, []string{"cached, tier M", "M *", "1 calls send 1 whole source files; the reader plans 4 tripwire candidates"}},
		{"calibration not cached", map[string]string{"app.py": "@flask"}, false, []string{"not cached: the scan calibrates first, at least"}},
		{"empty repository", nil, true, []string{"walk: 0 files, up to 0 source files go to discovery", "M *         0       0          0          0        0s"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := scanRepo(t, tt.files, "")
			code, out, errOut := runScanWith(offlineDeps(t, tt.cached), "estimate", "--config", cfg)
			if code != exitcode.OK {
				t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
			}
			for _, want := range append(tt.want, "no model was called", "tier S:", "tier L:") {
				if !strings.Contains(out, want) {
					t.Errorf("output lacks %q:\n%s", want, out)
				}
			}
			if _, err := os.Lstat(stateDir); !os.IsNotExist(err) {
				t.Errorf("estimate created %s: %v", stateDir, err)
			}
		})
	}
}

// Structural guard for invariants 1, 2 and 5: no estimate source names a
// transport, the gateway's client or egress log, or the scan's connect.
func TestEstimateSourceHasNoTransport(t *testing.T) {
	banned := map[string]bool{"connect": true, "connectGateway": true, "NewClient": true, "OpenEgressLog": true, "Through": true, "productionDeps": true}
	files, err := filepath.Glob("estimate*.go")
	if err != nil || len(files) < 3 {
		t.Fatalf("estimate sources: %v %v", files, err)
	}
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok && banned[id.Name] {
				t.Errorf("%s uses %s", name, id.Name)
			}
			return true
		})
	}
}

// A budget below the plan: the planner leaves sinks out for budget, the
// gateway caps are reported, and the scan is predicted incomplete.
func TestEstimateBudgetSmallerThanPlan(t *testing.T) {
	tests := []struct {
		name   string
		config string
		want   []string
	}{
		{"tokens", "budget:\n  max_tokens: 6000\n", []string{"budget", "the scan would end incomplete (reason budget, exit 4)"}},
		{"calls", "budget:\n  max_calls: 1\n", []string{"uncached calls, over budget.max_calls 1"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := scanRepo(t, map[string]string{"app.py": "@flask"}, tt.config)
			code, out, errOut := runScanWith(offlineDeps(t, true), "estimate", "--config", cfg)
			if code != exitcode.OK {
				t.Fatalf("exit %d\n%s", code, errOut)
			}
			for _, want := range tt.want {
				if !strings.Contains(out, want) {
					t.Errorf("output lacks %q:\n%s", want, out)
				}
			}
		})
	}
}

// Nothing from the repository reaches the output: not a file name, not a
// route string, not a control character it holds.
func TestEstimatePrintsNoRepositoryText(t *testing.T) {
	app := "from flask import Flask, request\nimport os\napp = Flask(__name__)\n\n@app.route(\"/zzleak\\x1b[31m\")\ndef zzleak():\n    return str(os.system(request.args[\"c\"]))\n"
	cfg := scanRepo(t, map[string]string{"zzsecretname.py": app, "zzbroken.go": "package x\n\x1b[2J"}, "")
	code, out, errOut := runScanWith(offlineDeps(t, true), "estimate", "--config", cfg)
	if code != exitcode.OK {
		t.Fatalf("exit %d\n%s", code, errOut)
	}
	if strings.Contains(out, "zz") || strings.ContainsAny(out, "\x1b\x00\r") {
		t.Fatalf("repository text in output:\n%q", out)
	}
	if !strings.Contains(out, "walk: 2 files, up to 2 source files") || !strings.Contains(out, "plans 1 tripwire candidates") {
		t.Fatalf("counts:\n%s", out)
	}
}

func TestEstimateArguments(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"path", []string{"estimate", "other"}},
		{"format", []string{"estimate", "--format", "json"}},
		{"negative price", []string{"estimate", "--price-in", "-1"}},
		{"NaN price", []string{"estimate", "--price-out", "NaN"}},
		{"Inf price", []string{"estimate", "--price-out", "Inf"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := scanRepo(t, nil, "")
			code, out, _ := runScanWith(offlineDeps(t, true), append(tt.args, "--config", cfg)...)
			if code != exitcode.ConfigError || out != "" {
				t.Fatalf("exit %d, stdout %q", code, out)
			}
		})
	}
}

// Acceptance (#15): on each testdata app the estimate is within ±30% of
// what a recorded scan spends. The fake model reports usage as a
// tokenizer would: pre-tokens of the decoded request (words with their
// leading space, digit runs of up to three, punctuation runs, spaces).
func TestEstimateWithin30Percent(t *testing.T) {
	for _, app := range []string{"flask", "fastapi", "express"} {
		t.Run(app, func(t *testing.T) {
			ext := ".py"
			if app == "express" {
				ext = ".js"
			}
			cfg := scanRepo(t, map[string]string{"app" + ext: "@" + app}, "")
			code, out, errOut := runScanWith(offlineDeps(t, true), "estimate", "--config", cfg)
			if code != exitcode.OK {
				t.Fatalf("estimate: exit %d\n%s", code, errOut)
			}
			calls, estIn, estOut := estimateRow(t, out, "M *")
			_, scanned, _ := runScanWith(usageDeps(&fakeModel{}), "scan", "--record", "--stats", "--config", cfg)
			sent, actIn, actOut := statsTotals(t, scanned)
			if calls != sent || calls == 0 {
				t.Fatalf("estimate %d calls, scan sent %d\n%s\n%s", calls, sent, out, scanned)
			}
			within(t, "input tokens", estIn, actIn)
			within(t, "total tokens", estIn+estOut, actIn+actOut)
			// After the recorded run, a default scan replays every call.
			_, again, _ := runScanWith(offlineDeps(t, true), "estimate", "--config", cfg)
			total, in, _ := estimateRow(t, again, "M *")
			if total != calls || in != 0 || !regexp.MustCompile(fmt.Sprintf(`M \* +%d +%d `, calls, calls)).MatchString(again) {
				t.Fatalf("recorded calls not counted as cached:\n%s", again)
			}
		})
	}
}

func within(t *testing.T, what string, est, actual int) {
	t.Helper()
	t.Logf("%s: estimate %d, actual %d", what, est, actual)
	if actual == 0 || est*10 < actual*7 || est*10 > actual*13 {
		t.Errorf("%s: estimate %d, actual %d: not within 30%%", what, est, actual)
	}
}

var rowFields = regexp.MustCompile(`\s+`)

// estimateRow returns calls, tokens in and tokens out of the tier row.
func estimateRow(t *testing.T, out, label string) (calls, in, outTokens int) {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(line, label+" ") {
			continue
		}
		f := rowFields.Split(strings.TrimSpace(strings.TrimPrefix(line, label)), -1)
		return atoi(t, f[0]), atoi(t, f[2]), atoi(t, f[3])
	}
	t.Fatalf("no %q row:\n%s", label, out)
	return 0, 0, 0
}

var (
	sentLine   = regexp.MustCompile(`model requests: \d+ \((\d+) sent`)
	tokensLine = regexp.MustCompile(`tokens sent: (\d+) in, (\d+) out`)
)

func statsTotals(t *testing.T, out string) (sent, in, outTokens int) {
	t.Helper()
	s, tok := sentLine.FindStringSubmatch(out), tokensLine.FindStringSubmatch(out)
	if s == nil || tok == nil {
		t.Fatalf("no stats:\n%s", out)
	}
	return atoi(t, s[1]), atoi(t, tok[1]), atoi(t, tok[2])
}

func atoi(t *testing.T, s string) int {
	t.Helper()
	n, err := strconv.Atoi(s)
	if err != nil {
		t.Fatalf("number %q: %v", s, err)
	}
	return n
}

// usageDeps is fakeDeps with each reply's usage set as a provider would.
func usageDeps(m *fakeModel) scanDeps {
	d := fakeDeps(m, calibrate.TierM)
	d.connect = func(*config.Resolved, string, io.Writer) (modelLink, error) {
		return modelLink{send: withUsage(m.send), close: func() error { return nil }}, nil
	}
	return d
}

func withUsage(send models.SendFunc) models.SendFunc {
	return func(ctx context.Context, c gateway.Call) (*gateway.Reply, error) {
		r, err := send(ctx, c)
		if err != nil {
			return r, err
		}
		var reply struct {
			Choices []struct {
				Message struct {
					Content string `json:"content"`
				} `json:"message"`
			} `json:"choices"`
		}
		var request any
		if err := json.Unmarshal(r.Body, &reply); err != nil || len(reply.Choices) != 1 {
			return nil, errors.New("usage: unexpected reply")
		}
		if err := json.Unmarshal(c.Payload, &request); err != nil {
			return nil, err
		}
		r.Body, err = chatReplyUsage(reply.Choices[0].Message.Content, pretokens(jsonText(request)))
		return r, err
	}
}

// chatReplyUsage is a reply with content and provider-style token counts.
func chatReplyUsage(content string, promptTokens int) ([]byte, error) {
	return json.Marshal(map[string]any{
		"id": "chatcmpl-fake", "object": "chat.completion", "model": "test-model",
		"choices": []any{map[string]any{"index": 0, "message": map[string]any{"role": "assistant", "content": content}, "finish_reason": "stop"}},
		"usage":   map[string]int{"prompt_tokens": promptTokens, "completion_tokens": pretokens(content)},
	})
}

// pretoken is the cl100k pre-tokenizer pattern without its lookahead.
var pretoken = regexp.MustCompile(`'(?:s|t|re|ve|m|ll|d)| ?\pL+| ?\pN{1,3}| ?[^\s\pL\pN]+|\s+`)

func pretokens(s string) int { return len(pretoken.FindAllStringIndex(s, -1)) }

// jsonText is every key and string of a decoded request, as the model
// sees them: the messages, and the schema the provider adds to the prompt.
func jsonText(v any) string {
	var b strings.Builder
	var walk func(any)
	walk = func(v any) {
		switch x := v.(type) {
		case string:
			b.WriteString(x + " ")
		case []any:
			for _, e := range x {
				walk(e)
			}
		case map[string]any:
			for k, e := range x {
				b.WriteString(k + " ")
				walk(e)
			}
		}
	}
	walk(v)
	return b.String()
}

// A planner that refuses its input makes the estimate predict what the
// scan does: every sink skipped as planner_rejected and the run
// incomplete, also when there is no sink at all.
func TestTierEstimateRejected(t *testing.T) {
	for _, n := range []int{0, 1, 3} {
		t.Run(strconv.Itoa(n), func(t *testing.T) {
			findings := make([]report.Finding, n)
			got := tierEstimate{skipped: map[string]int{"other": 2}}.rejected(findings, nil)
			if got.skipped[reasonPlannerRejected] != n || got.skipped["other"] != 2 {
				t.Errorf("skipped %v, want %d %s and the other reason kept", got.skipped, n, reasonPlannerRejected)
			}
			if got.incomplete != reasonPlannerRejected {
				t.Errorf("incomplete %q, want %q", got.incomplete, reasonPlannerRejected)
			}
		})
	}
}
