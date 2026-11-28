package calibrate

import (
	"context"
	"errors"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/sneakercreepers/creep/internal/gateway"
	"github.com/sneakercreepers/creep/internal/models"
)

// Acceptance (#90, #358): a recorded run replays to the same scores and
// tier, with no network and no key, and a fixture covers each of S, M and
// L (fixture_test.go says what each synthesized model gets wrong).
func TestRunReplayIsDeterministic(t *testing.T) {
	for _, fm := range fixtureModels() {
		t.Run(fm.name, func(t *testing.T) {
			if *updateFixtures {
				recordFixture(t, fm)
			}
			var first Result
			for i := range 2 {
				rep, n := fromFixture(t, fm.name)
				r, err := Run(context.Background(), testOptions(t, 1, rep.send))
				if err != nil {
					t.Fatal(err)
				}
				if rep.replies != n || len(rep.calls) != n {
					t.Fatalf("run used %d of %d recorded replies in %d calls", rep.replies, n, len(rep.calls))
				}
				if i == 1 && !reflect.DeepEqual(r, first) {
					t.Fatalf("replay differs:\n%+v\n%+v", r, first)
				}
				first = r
			}
			checkFixtureResult(t, fm, first)
		})
	}
}

// The fixtures cover every tier assignTier can return.
func TestFixturesCoverEveryTier(t *testing.T) {
	covered := map[Tier]bool{}
	for _, fm := range fixtureModels() {
		covered[fm.tier] = true
	}
	for _, tier := range Tiers() {
		if !covered[tier] {
			t.Errorf("no replay fixture for tier %s", tier)
		}
	}
}

// Calls go out one at a time in a fixed order (tasks, tool probes, context
// probes), each logged with its purpose, so a recording replays exactly.
func TestRunCallOrder(t *testing.T) {
	rep, _ := fromFixture(t, "seed1_tier_m")
	if _, err := Run(context.Background(), testOptions(t, 1, rep.send)); err != nil {
		t.Fatal(err)
	}
	var purposes []string
	for _, c := range rep.calls {
		if len(purposes) == 0 || purposes[len(purposes)-1] != c.Purpose {
			purposes = append(purposes, c.Purpose)
		}
	}
	want := []string{purposeTask, purposeTool, purposeContext}
	if !reflect.DeepEqual(purposes, want) {
		t.Errorf("purpose runs = %v, want %v", purposes, want)
	}
}

// Only the code reaches the model: the template name, task ID and class,
// which are the answer key, never appear in a task's user turn.
func TestTaskPromptHoldsNoAnswerKey(t *testing.T) {
	o := newOracle(t, 1)
	rep := answering(o.answer)
	if _, err := Run(context.Background(), testOptions(t, 1, rep.send)); err != nil {
		t.Fatal(err)
	}
	for _, c := range rep.calls {
		if c.Purpose != purposeTask {
			continue
		}
		user := userTurn(c.Payload)
		for _, task := range o.tasks {
			for _, key := range []string{task.Template, task.ID} {
				if strings.Contains(user, key) {
					t.Fatalf("task prompt holds answer key %q", key)
				}
			}
		}
		// A class may be part of a word ("sqlite3"), never a word itself.
		for _, class := range Classes() {
			if regexp.MustCompile(`\b` + string(class) + `\b`).MatchString(user) {
				t.Fatalf("task prompt names class %q", class)
			}
		}
	}
}

func TestRunOutcomes(t *testing.T) {
	o := newOracle(t, 1)
	tests := []struct {
		name       string
		answer     func(user string) string
		tier       Tier
		correct    int
		structured StructuredCheck
		tools      int
		context    int
	}{
		{"perfect model", o.answer, TierL, 64, StructuredCheck{64, 0, true}, 3, 128 << 10},
		{"all wrong", func(user string) string { return opposite(o, user) }, TierS, 0, StructuredCheck{64, 0, true}, 0, 0},
		{"always safe", func(string) string { return taskJSON(false, "", 0) }, TierS, 32, StructuredCheck{64, 0, true}, 0, 0},
		{"invalid output", func(string) string { return `{"vulnerable":true,"class":"xss","line":1}` }, TierS, 0, StructuredCheck{64, 64, false}, 0, 0},
		{"not json", func(string) string { return "I think it is fine." }, TierS, 0, StructuredCheck{64, 64, false}, 0, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := Run(context.Background(), testOptions(t, 1, answering(tt.answer).send))
			if err != nil {
				t.Fatal(err)
			}
			if r.Tier != tt.tier || r.Overall.Correct != tt.correct || r.Structured != tt.structured {
				t.Errorf("tier %s, correct %d, structured %+v", r.Tier, r.Overall.Correct, r.Structured)
			}
			if r.Tools.Correct != tt.tools || r.Context.EffectiveBytes != tt.context {
				t.Errorf("tools %d, context %d", r.Tools.Correct, r.Context.EffectiveBytes)
			}
		})
	}
}

// opposite answers every call wrongly but validly.
func opposite(o oracle, user string) string {
	if task, ok := o.task(user); ok {
		return taskJSON(!task.Vulnerable, "ssrf", 1)
	}
	if strings.Contains(user, "what string is assigned") {
		return `{"value":"wrong"}`
	}
	return `{"tool":"list_dir","argument":"nowhere"}`
}

// A failure that is not the model's output ends the run with no Result: a
// partial calibration never gets a tier.
func TestRunFailures(t *testing.T) {
	o := newOracle(t, 1)
	statusAt := func(call int, status int) *replayer {
		return &replayer{next: func(n int, c gateway.Call) (recordedReply, bool) {
			if n == call {
				return recordedReply{Status: status, Body: openAIBody("")}, true
			}
			return recordedReply{Status: 200, Body: openAIBody(o.answer(userTurn(c.Payload)))}, true
		}}
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	tests := []struct {
		name string
		ctx  context.Context
		opts func(t *testing.T) Options
		want error
	}{
		{"status on a task", context.Background(), func(t *testing.T) Options { return testOptions(t, 1, statusAt(0, 500).send) }, models.ErrStatus},
		{"status on a tool probe", context.Background(), func(t *testing.T) Options { return testOptions(t, 1, statusAt(TaskCount+1, 429).send) }, models.ErrStatus},
		{"status on a context probe", context.Background(), func(t *testing.T) Options { return testOptions(t, 1, statusAt(TaskCount+4, 503).send) }, models.ErrStatus},
		{"transport error", context.Background(), func(t *testing.T) Options { return testOptions(t, 1, (&replayer{next: noReply}).send) }, nil},
		{"canceled", canceled, func(t *testing.T) Options { return testOptions(t, 1, contextSend) }, context.Canceled},
		{"no model", context.Background(), func(t *testing.T) Options { return Options{Seed: 1, Redactor: newRedactor(t)} }, ErrOptions},
		{"no redactor", context.Background(), func(t *testing.T) Options { return Options{Seed: 1, Model: newModel(t, contextSend)} }, ErrOptions},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := Run(tt.ctx, tt.opts(t))
			if err == nil {
				t.Fatal("run succeeded")
			}
			if tt.want != nil && !errors.Is(err, tt.want) {
				t.Errorf("err = %v, want %v", err, tt.want)
			}
			if !reflect.DeepEqual(r, Result{}) {
				t.Errorf("failed run returned a result: %+v", r)
			}
		})
	}
}

func noReply(int, gateway.Call) (recordedReply, bool) { return recordedReply{}, false }

// Replies are matched to their request hash: other tasks (another seed)
// with the same call count do not replay against the recording.
func TestReplayRefusesOtherRequests(t *testing.T) {
	rep, _ := fromFixture(t, "seed1_tier_m")
	if _, err := Run(context.Background(), testOptions(t, 2, rep.send)); err == nil {
		t.Fatal("seed 2 replayed against the seed 1 recording")
	}
	if rep.replies != 0 {
		t.Errorf("served %d replies to requests it was not recorded for", rep.replies)
	}
}

// failContextCall answers like o, except that context-probe call n (0 for
// 8 KiB, 1 for 32 KiB, 2 for 128 KiB) gets status, or err when set.
func failContextCall(o oracle, n, status int, err error) models.SendFunc {
	rep := answering(o.answer)
	seen := 0
	return func(ctx context.Context, call gateway.Call) (*gateway.Reply, error) {
		if call.Purpose == purposeContext {
			seen++
			if seen-1 == n && err != nil {
				return nil, err
			}
			if seen-1 == n {
				return &gateway.Reply{ID: "refused", Status: status, Body: openAIBody("")}, nil
			}
		}
		return rep.send(ctx, call)
	}
}

// contextReply answers like o, except that every attempt at context probe
// n (0 for 8 KiB, 1 for 32 KiB, 2 for 128 KiB), retries included, gets
// content.
func contextReply(o oracle, n int, content string) models.SendFunc {
	rep := answering(o.answer)
	return func(ctx context.Context, call gateway.Call) (*gateway.Reply, error) {
		if call.Purpose == purposeContext && contextProbeIndex(call.Payload) == n {
			return &gateway.Reply{ID: "fixed", Status: 200, Body: openAIBody(content)}, nil
		}
		return rep.send(ctx, call)
	}
}

// contextProbeIndex tells the probes apart by payload size: a probe is
// just over its size, and a retry that repeats it stays below the next.
func contextProbeIndex(payload []byte) int {
	switch {
	case len(payload) < 32<<10:
		return 0
	case len(payload) < 128<<10:
		return 1
	}
	return 2
}

// A context probe refused for its size (400, 413, budget) measures the
// context: the smaller sizes' result stands and the run gets a tier. A
// refusal that is not about size still ends the run. Every stop records
// its size and reason (#174), so a 400 on the 8 KiB probe, which leaves
// the model at tier S, is visible in the Result.
func TestContextProbeRefusals(t *testing.T) {
	o := newOracle(t, 1)
	stop := func(effective, at int, why ContextStop, status int) ContextCheck {
		return ContextCheck{EffectiveBytes: effective << 10, StoppedAt: at << 10, Stop: why, Status: status}
	}
	tests := []struct {
		name  string
		send  models.SendFunc
		check ContextCheck
		tier  Tier
		want  error
	}{
		{"every size answered", answering(o.answer).send, ContextCheck{EffectiveBytes: 128 << 10}, TierL, nil},
		{"400 at 128 KiB", failContextCall(o, 2, 400, nil), stop(32, 128, ContextStopStatus, 400), TierM, nil},
		{"413 at 32 KiB", failContextCall(o, 1, 413, nil), stop(8, 32, ContextStopStatus, 413), TierS, nil},
		{"400 at 8 KiB", failContextCall(o, 0, 400, nil), stop(0, 8, ContextStopStatus, 400), TierS, nil},
		{"budget at 128 KiB", failContextCall(o, 2, 0, &gateway.BudgetError{}), stop(32, 128, ContextStopBudget, 0), TierM, nil},
		{"wrong answer at 32 KiB", contextReply(o, 1, `{"value":"wrong-value-0000"}`), stop(8, 32, ContextStopWrongAnswer, 0), TierS, nil},
		{"invalid output at 8 KiB", contextReply(o, 0, "not json"), stop(0, 8, ContextStopInvalidOutput, 0), TierS, nil},
		{"503 at 128 KiB", failContextCall(o, 2, 503, nil), ContextCheck{}, "", models.ErrStatus},
		{"not allowed at 128 KiB", failContextCall(o, 2, 0, gateway.ErrNotAllowed), ContextCheck{}, "", gateway.ErrNotAllowed},
		{"no consent at 128 KiB", failContextCall(o, 2, 0, gateway.ErrNoConsent), ContextCheck{}, "", gateway.ErrNoConsent},
		{"egress write at 128 KiB", failContextCall(o, 2, 0, gateway.ErrUnsafeLogPath), ContextCheck{}, "", gateway.ErrUnsafeLogPath},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := Run(context.Background(), testOptions(t, 1, tt.send))
			if tt.want != nil {
				if !errors.Is(err, tt.want) || !reflect.DeepEqual(r, Result{}) {
					t.Fatalf("err = %v, result %+v; want %v and no result", err, r, tt.want)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if r.Context != tt.check || r.Tier != tt.tier {
				t.Errorf("context %+v tier %s, want %+v %s", r.Context, r.Tier, tt.check, tt.tier)
			}
			if !r.Context.consistent() {
				t.Errorf("context %+v is not consistent", r.Context)
			}
		})
	}
}

func TestRunRefusesNoTasks(t *testing.T) {
	_, err := run(context.Background(), testOptions(t, 1, contextSend), nil)
	if !errors.Is(err, ErrOptions) {
		t.Fatalf("err = %v, want ErrOptions", err)
	}
}
