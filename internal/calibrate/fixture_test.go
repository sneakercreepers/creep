package calibrate

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/sneakercreepers/creep/internal/gateway"
	"github.com/sneakercreepers/creep/internal/models"
)

var updateFixtures = flag.Bool("update", false, "rewrite testdata/replay from the synthesized models")

// mistakes is what a synthesized model gets wrong, per class, on the first
// tasks of that class in Generate's order. Everything else it answers
// like the oracle.
type mistakes struct {
	miss    map[Class]int // vulnerable tasks answered safe
	lineOff map[Class]int // vulnerable tasks answered three lines below the sink
	flag    map[Class]int // safe twins flagged in their class
	invalid map[Class]int // safe twins answered with no JSON, retry included
	// contextWrong is the first context probe answered wrongly (0 for
	// 8 KiB, 1 for 32 KiB, 2 for 128 KiB); 3 answers all of them.
	contextWrong int
}

// fixtureModel is one synthesized replay fixture of seed 1 and the
// Result it must replay to. The fixtures are synthesized until a live
// recording of a neutral calibration replaces them (#358); regenerate
// them with:
//
//	go test ./internal/calibrate -run TestRunReplayIsDeterministic -update
type fixtureModel struct {
	name    string
	tier    Tier
	errs    mistakes
	correct int
	classes map[Class]int // correct per class; 8 when not listed
	invalid int
	context ContextCheck
	planned Fitness
}

func fixtureModels() []fixtureModel {
	stop := func(effective, at int) ContextCheck {
		return ContextCheck{EffectiveBytes: effective << 10, StoppedAt: at << 10, Stop: ContextStopWrongAnswer}
	}
	return []fixtureModel{
		{
			// Fit, but blind to code injection and short of context.
			name: "seed1_tier_s", tier: TierS,
			errs:    mistakes{miss: map[Class]int{ClassCodeInjection: 4}, invalid: map[Class]int{ClassPathTraversal: 1}, contextWrong: 1},
			correct: 59, classes: map[Class]int{ClassCodeInjection: 4, ClassPathTraversal: 7}, invalid: 1, context: stop(8, 32),
			planned: Fitness{Fit: true, Planned: ClassScore{Score: newScore(59, 64), SafeTwins: 32, SafeFlagged: 1}},
		},
		{
			name: "seed1_tier_m", tier: TierM,
			errs: mistakes{
				miss: map[Class]int{ClassCodeInjection: 2}, lineOff: map[Class]int{ClassSQLi: 1},
				flag: map[Class]int{ClassTemplateInjection: 1}, invalid: map[Class]int{ClassSSRF: 1}, contextWrong: 2,
			},
			correct: 59, invalid: 1, context: stop(32, 128),
			classes: map[Class]int{ClassCodeInjection: 6, ClassSQLi: 7, ClassTemplateInjection: 7, ClassSSRF: 7},
			planned: Fitness{Fit: true, Planned: ClassScore{Score: newScore(59, 64), SafeTwins: 32, SafeFlagged: 2}},
		},
		{
			name: "seed1_tier_l", tier: TierL,
			errs:    mistakes{lineOff: map[Class]int{ClassDeserialization: 1}, contextWrong: 3},
			correct: 63, classes: map[Class]int{ClassDeserialization: 7}, context: ContextCheck{EffectiveBytes: 128 << 10},
			planned: Fitness{Fit: true, Planned: ClassScore{Score: newScore(63, 64), SafeTwins: 32}},
		},
	}
}

// synthesized answers like o except for m's mistakes.
func synthesized(o oracle, m mistakes) models.SendFunc {
	wrong := map[string]string{}
	seen := map[Class]map[string]int{}
	for _, task := range o.tasks {
		if seen[task.Class] == nil {
			seen[task.Class] = map[string]int{}
		}
		wrong[task.ID] = mistakeFor(task, m, seen[task.Class])
	}
	retrying := false
	return func(_ context.Context, call gateway.Call) (*gateway.Reply, error) {
		user := userTurn(call.Payload)
		content := o.answer(user)
		task, isTask := o.task(user)
		switch {
		case isTask && wrong[task.ID] != "":
			content = wrong[task.ID]
		case !isTask && retrying:
			content = "not json"
		case call.Purpose == purposeContext && contextProbeIndex(call.Payload) >= m.contextWrong:
			content = `{"value":"wrong-value-0000"}`
		}
		retrying = content == "not json"
		return &gateway.Reply{ID: "synthesized", Status: 200, Body: openAIBody(content)}, nil
	}
}

// mistakeFor is the wrong answer task gets, or "" for the oracle's. n
// counts the class's tasks already given each kind of mistake.
func mistakeFor(task Task, m mistakes, n map[string]int) string {
	take := func(kind string, quota map[Class]int) bool {
		if n[kind] >= quota[task.Class] {
			return false
		}
		n[kind]++
		return true
	}
	switch {
	case task.Vulnerable && take("miss", m.miss):
		return taskJSON(false, "", 0)
	case task.Vulnerable && take("line", m.lineOff):
		return taskJSON(true, string(task.Class), task.Line+lineTolerance+1)
	case !task.Vulnerable && take("flag", m.flag):
		return taskJSON(true, string(task.Class), task.Line)
	case !task.Vulnerable && take("invalid", m.invalid):
		return "not json"
	}
	return ""
}

// recordFixture runs a synthesized calibration and writes every reply,
// keyed on its request hash, to testdata/replay/<name>.json.
func recordFixture(t *testing.T, fm fixtureModel) {
	t.Helper()
	send := synthesized(newOracle(t, 1), fm.errs)
	var recs []recordedReply
	record := func(ctx context.Context, call gateway.Call) (*gateway.Reply, error) {
		reply, err := send(ctx, call)
		if err == nil {
			recs = append(recs, recordedReply{Request: payloadHash(call.Payload), Status: reply.Status, Body: reply.Body})
		}
		return reply, err
	}
	if _, err := Run(context.Background(), testOptions(t, 1, record)); err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	b.WriteString("[\n")
	for i, rec := range recs {
		line, err := json.Marshal(rec)
		if err != nil {
			t.Fatal(err)
		}
		b.Write(line)
		if i < len(recs)-1 {
			b.WriteString(",")
		}
		b.WriteString("\n")
	}
	b.WriteString("]\n")
	if err := os.WriteFile(filepath.Join("testdata", "replay", fm.name+".json"), b.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

func checkFixtureResult(t *testing.T, fm fixtureModel, r Result) {
	t.Helper()
	if r.Tier != fm.tier {
		t.Errorf("tier = %s, want %s", r.Tier, fm.tier)
	}
	if r.Overall.Correct != fm.correct || r.Overall.Total != TaskCount {
		t.Errorf("overall = %d/%d, want %d/%d", r.Overall.Correct, r.Overall.Total, fm.correct, TaskCount)
	}
	for _, c := range r.Classes {
		want, ok := fm.classes[c.Class]
		if !ok {
			want = classTasks
		}
		if c.Correct != want || c.Total != classTasks {
			t.Errorf("%s = %d/%d, want %d/%d", c.Class, c.Correct, c.Total, want, classTasks)
		}
	}
	checks := r.Structured == newStructuredCheck(TaskCount, fm.invalid) &&
		r.Tools == ToolCheck{Probes: 3, Correct: 3, Passed: true} && r.Context == fm.context
	if !checks {
		t.Errorf("checks = %+v %+v %+v", r.Structured, r.Tools, r.Context)
	}
	if !r.Fitness.sameVerdict(fm.planned) {
		t.Errorf("fitness %+v, want %+v", r.Fitness, fm.planned)
	}
	tasks := mustGenerate(t, 1)
	if r.Seed != 1 || r.TaskSet != taskSetHash(tasks) || r.PromptVersion != PromptVersion {
		t.Errorf("result does not identify its tasks: %d %s %d", r.Seed, r.TaskSet, r.PromptVersion)
	}
}
