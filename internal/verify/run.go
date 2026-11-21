package verify

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/sneakercreepers/creep/internal/sandbox"
)

// Runner is what Run needs of the sandbox: the runner container that
// sends raw requests to the app on the run network, the marker lookup in
// the run's database, and the content of the canary file planted in the
// app's container. *sandbox.Sandbox implements it.
type Runner interface {
	Exchange(ctx context.Context, port int, requests [][]byte) ([]sandbox.Exchange, error)
	DatabaseHasTable(ctx context.Context, table string) (bool, error)
	AppCanary() string
}

var _ Runner = (*sandbox.Sandbox)(nil)

// Target is the app under test. Its host is always sandbox.AppHost.
type Target struct {
	Port     int  // the app's port on the run network
	Database bool // the run's database is up (sandbox.StartDatabase)
}

// Outcome is how one run of a PoC ended. Only Verified means the oracle
// held.
type Outcome string

const (
	Verified    Outcome = "verified"
	NotVerified Outcome = "not_verified" // the app answered; the oracle did not hold
	NoResponse  Outcome = "no_response"  // a request got no HTTP response
	AuthFailed  Outcome = "auth_failed"  // http_sequence: the auth request gave no session
	NoDatabase  Outcome = "no_database"  // sql_payload marker without a run database
)

// Oracle names in a Result, beside OracleReflect.
const (
	OracleDelay      = "delay"       // sql_payload delay: payload slower than the baselines around it
	OracleDBMarker   = "db_marker"   // sql_payload marker: the table exists
	OracleFileMarker = "file_marker" // path_payload: the canary file's content in the payload response only
)

// minCanary is the shortest canary content Run accepts: anything shorter
// could be in a response by chance.
const minCanary = 16

// Step roles.
const (
	RoleAuth     = "auth"
	RoleRequest  = "request"
	RoleBaseline = "baseline"
	RolePayload  = "payload"
)

// Step is one request the runner sent and what came back, in order: what
// a reproduction bundle keeps (#25).
type Step struct {
	Role      string
	Request   []byte
	Response  []byte
	Truncated bool
	Elapsed   time.Duration
}

// Result is one run of a PoC.
type Result struct {
	Template string
	Oracle   string
	Outcome  Outcome
	Steps    []Step
}

// ErrRunner marks a runner that answered a different number of requests
// than it was sent, or has no canary file in the app for path_payload.
var ErrRunner = errors.New("verify runner answer")

// Run runs the PoC once against the target through r and judges it with
// the template's oracle. Each run has a fresh nonce, so repeated runs of
// one PoC are independent. A sandbox error (the canary aborted the run, a
// timeout, Ctrl+C) is returned as is; how the app answered is the Outcome.
func Run(ctx context.Context, r Runner, t Target, p PoC) (Result, error) {
	nonce, err := newNonce()
	if err != nil {
		return Result{}, err
	}
	return run(ctx, r, t, p, nonce)
}

func run(ctx context.Context, r Runner, t Target, p PoC, nonce string) (Result, error) {
	if !p.built {
		return Result{}, fmt.Errorf("run: not a PoC from Build: %w", ErrInvalid)
	}
	if t.Port < 1 || t.Port > 65535 {
		return Result{}, fmt.Errorf("run: port %d: %w", t.Port, ErrInvalid)
	}
	switch req := p.req; {
	case req.HTTPRequest != nil:
		return runRequest(ctx, r, t, req.HTTPRequest, nonce)
	case req.HTTPSequence != nil:
		return runSequence(ctx, r, t, req.HTTPSequence, nonce)
	case req.SQLPayload != nil:
		return runSQL(ctx, r, t, req.SQLPayload, nonce)
	}
	return runPath(ctx, r, t, p.req.PathPayload)
}

func runRequest(ctx context.Context, r Runner, t Target, params *HTTPRequest, nonce string) (Result, error) {
	res := Result{Template: TemplateHTTPRequest, Oracle: params.Oracle.Kind}
	steps, err := exchange(ctx, r, t.Port, Step{Role: RoleRequest, Request: render(params.Request, t.Port, fill{nonce: nonceValue(nonce)})})
	if err != nil {
		return Result{}, err
	}
	res.Steps, res.Outcome = steps, judgeCall(params.Oracle, steps[0], nonce)
	return res, nil
}

func runSequence(ctx context.Context, r Runner, t Target, params *HTTPSequence, nonce string) (Result, error) {
	res := Result{Template: TemplateHTTPSequence, Oracle: params.Oracle.Kind}
	auth, err := exchange(ctx, r, t.Port, Step{Role: RoleAuth, Request: render(params.Auth, t.Port, fill{})})
	if err != nil {
		return Result{}, err
	}
	res.Steps = auth
	answer, ok := parseResponse(auth[0].Response)
	if !ok {
		res.Outcome = NoResponse
		return res, nil
	}
	sess, ok := session(params.Session, params.TokenField, answer)
	if answer.status >= 400 || !ok {
		res.Outcome = AuthFailed
		return res, nil
	}
	f := fill{nonce: nonceValue(nonce), session: &sess}
	steps, err := exchange(ctx, r, t.Port, Step{Role: RoleRequest, Request: render(params.Request, t.Port, f)})
	if err != nil {
		return Result{}, err
	}
	res.Steps, res.Outcome = append(res.Steps, steps...), judgeCall(params.Oracle, steps[0], nonce)
	return res, nil
}

// judgeCall is the oracle of http_request and http_sequence: creep's
// probe, unescaped, in an HTML body. The status the model expects only
// narrows it; it never verifies on its own.
func judgeCall(o Oracle, s Step, nonce string) Outcome {
	answer, ok := parseResponse(s.Response)
	switch {
	case !ok:
		return NoResponse
	case o.Status != 0 && answer.status != o.Status:
		return NotVerified
	case answer.html() && bytes.Contains(answer.body, []byte(probe(nonce))):
		return Verified
	}
	return NotVerified
}

// runSQL sends the payload between two baselines in one runner for delay,
// or the payload alone for marker, then looks for the marker table.
func runSQL(ctx context.Context, r Runner, t Target, params *SQLPayload, nonce string) (Result, error) {
	table := markerTable(nonce)
	payload := sqlValue(sqlPayload(params.Context, params.Technique, table))
	if params.Technique == "delay" {
		return runDelay(ctx, r, t, params, payload)
	}
	res := Result{Template: TemplateSQLPayload, Oracle: OracleDBMarker, Outcome: NoDatabase}
	if !t.Database {
		return res, nil
	}
	steps, err := exchange(ctx, r, t.Port, Step{Role: RolePayload, Request: render(params.Request, t.Port, fill{payload: payload})})
	if err != nil {
		return Result{}, err
	}
	if res.Outcome, err = judgeMarker(ctx, r, table, steps[0]); err != nil {
		return Result{}, err
	}
	res.Steps = steps
	return res, nil
}

// runDelay sends a baseline, the payload and a baseline again from one
// runner, so an app that slows a later request down (a rate limit, a
// tarpit) slows the last baseline too.
func runDelay(ctx context.Context, r Runner, t Target, params *SQLPayload, payload value) (Result, error) {
	baseline := render(params.Request, t.Port, fill{payload: sqlValue(sqlBaseline[params.Context])})
	steps, err := exchange(ctx, r, t.Port,
		Step{Role: RoleBaseline, Request: baseline},
		Step{Role: RolePayload, Request: render(params.Request, t.Port, fill{payload: payload})},
		Step{Role: RoleBaseline, Request: baseline})
	if err != nil {
		return Result{}, err
	}
	res := Result{Template: TemplateSQLPayload, Oracle: OracleDelay, Steps: steps, Outcome: answered(steps)}
	if res.Outcome == "" {
		res.Outcome = judgeDelay(steps[0].Elapsed, steps[1].Elapsed, steps[2].Elapsed)
	}
	return res, nil
}

// judgeDelay: the payload took delayMargin longer than each baseline.
func judgeDelay(before, payload, after time.Duration) Outcome {
	if payload-before >= delayMargin && payload-after >= delayMargin {
		return Verified
	}
	return NotVerified
}

// judgeMarker: the table is the oracle. Without it, a payload that got no
// answer at all is no response.
func judgeMarker(ctx context.Context, r Runner, table string, s Step) (Outcome, error) {
	found, err := r.DatabaseHasTable(ctx, table)
	if err != nil {
		return "", fmt.Errorf("run: %w", err)
	}
	switch _, answered := parseResponse(s.Response); {
	case found:
		return Verified, nil
	case !answered:
		return NoResponse, nil
	}
	return NotVerified, nil
}

// runPath sends the request with a harmless file name, then with the path
// to creep's canary file. Only an app that reads that file can put its
// content, which neither the model nor the repository knows, in a
// response.
func runPath(ctx context.Context, r Runner, t Target, params *PathPayload) (Result, error) {
	canary := r.AppCanary()
	if len(canary) < minCanary {
		return Result{}, fmt.Errorf("run: no canary file in the app: %w", ErrRunner)
	}
	baseline := value{wire: baselineFile, text: baselineFile}
	steps, err := exchange(ctx, r, t.Port,
		Step{Role: RoleBaseline, Request: render(params.Request, t.Port, fill{payload: baseline})},
		Step{Role: RolePayload, Request: render(params.Request, t.Port, fill{payload: pathPayload(params.Style, params.Depth)})})
	if err != nil {
		return Result{}, err
	}
	res := Result{Template: TemplatePathPayload, Oracle: OracleFileMarker, Steps: steps, Outcome: answered(steps)}
	if res.Outcome != "" {
		return res, nil
	}
	base, _ := parseResponse(steps[0].Response)
	got, _ := parseResponse(steps[1].Response)
	res.Outcome = NotVerified
	if bytes.Contains(got.body, []byte(canary)) && !bytes.Contains(base.body, []byte(canary)) {
		res.Outcome = Verified
	}
	return res, nil
}

// answered is NoResponse if a step got no HTTP response, else empty: the
// oracle decides.
func answered(steps []Step) Outcome {
	for _, s := range steps {
		if _, ok := parseResponse(s.Response); !ok {
			return NoResponse
		}
	}
	return ""
}

// exchange sends each step's request through the runner, in one
// container, and fills in what came back.
func exchange(ctx context.Context, r Runner, port int, steps ...Step) ([]Step, error) {
	requests := make([][]byte, len(steps))
	for i, s := range steps {
		requests[i] = s.Request
	}
	got, err := r.Exchange(ctx, port, requests)
	if err != nil {
		return nil, fmt.Errorf("run: %w", err)
	}
	if len(got) != len(steps) {
		return nil, fmt.Errorf("run: %d answers to %d requests: %w", len(got), len(steps), ErrRunner)
	}
	for i := range steps {
		s := &steps[i]
		s.Response, s.Truncated, s.Elapsed = got[i].Response, got[i].Truncated, got[i].Elapsed
	}
	return steps, nil
}
