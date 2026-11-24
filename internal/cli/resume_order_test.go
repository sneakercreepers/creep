package cli

import (
	"bytes"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sneakercreepers/creep/internal/config"
	"github.com/sneakercreepers/creep/internal/state"
)

// orderKey is a valid cache key named by one hex digit.
func orderKey(c string) state.Key {
	return state.Key{ContentHash: strings.Repeat(c, 64), Model: "test-model", PromptVersion: "reader.v1"}
}

// resumedSession is a session resuming a run that finished steps, each
// built from a "cache:<digit>" or plain step name, with every finished
// reply recorded in its store as "reply <digit>".
func resumedSession(t *testing.T, secret byte, steps []string) *session {
	t.Helper()
	store, err := state.OpenWithSecret(filepath.Join(t.TempDir(), ".creep"), bytes.Repeat([]byte{secret}, state.SecretBytes))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	var recorded []string
	for _, step := range steps {
		c, ok := strings.CutPrefix(step, "cache:")
		if !ok {
			recorded = append(recorded, step)
			continue
		}
		reply := []byte("reply " + c)
		if _, err := store.Respond(state.ModeRecord, orderKey(c), func() ([]byte, error) { return reply, nil }); err != nil {
			t.Fatal(err)
		}
		recorded = append(recorded, state.CacheStep(orderKey(c), reply))
	}
	run, err := store.NewRunWith(state.ModeLive, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = run.Close() })
	return &session{store: store, run: run, resume: newResumeState(state.Summary{Steps: recorded})}
}

// Regression (v0.4 review A1): a resume serves every finished step before
// it sends anything new. A step it had not reached, asked while a finished
// one is unserved, is refused with nothing sent, and the run stays
// refused. Calibration's steps, recorded before the tier, are not owed:
// a resume reads the calibration from its cache.
func TestResumeServesFinishedStepsFirst(t *testing.T) {
	tests := []struct {
		name    string
		steps   []string
		asks    string // the keys asked, in order
		refused bool
		sent    int
	}{
		{"finished then new", []string{"tier:M", "cache:a"}, "ab", false, 1},
		{"new before a finished one", []string{"tier:M", "cache:a"}, "ba", true, 0},
		{"one of two finished skipped", []string{"tier:M", "cache:a", "cache:c"}, "ab", true, 0},
		{"calibration steps not owed", []string{"cache:c", "tier:M", "cache:a"}, "ab", false, 1},
		{"no tier yet, nothing owed", []string{"cache:c"}, "b", false, 1},
		{"a new scan owes nothing", nil, "b", false, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := resumedSession(t, 7, tt.steps)
			sent := 0
			call := func() ([]byte, error) { sent++; return []byte("new reply"), nil }
			var err error
			for _, c := range tt.asks {
				if _, askErr := s.respond(orderKey(string(c)), call); askErr != nil && err == nil {
					err = askErr
				}
			}
			if refused := errors.Is(err, errOutOfOrder); refused != tt.refused || (!tt.refused && err != nil) {
				t.Fatalf("err = %v; want refused %v", err, tt.refused)
			}
			if sent != tt.sent {
				t.Fatalf("%d calls sent, want %d", sent, tt.sent)
			}
		})
	}
}

// Regression (v0.4 release pentest P2, review A11): the header's endpoint
// digest covers the values of model.env, so a resume whose GEMINI_MODEL
// changed is refused, and every header value is keyed with the user's state
// secret: it holds no value in clear and differs for another user.
func TestHeaderCoversModelEnvValues(t *testing.T) {
	model := config.Model{Contract: "command", Preset: "gemini", Env: []string{"GEMINI_API_KEY", "GEMINI_MODEL"}}
	header := func(secret byte, value string) state.Header {
		t.Setenv("GEMINI_MODEL", value)
		s := resumedSession(t, secret, nil)
		s.cfg.Model = model
		h, err := s.header()
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	a, b := header(7, "gemini-a"), header(7, "gemini-b")
	err := compareHeader(a, b)
	var refusal *resumeRefusal
	if !errors.As(err, &refusal) || !strings.Contains(err.Error(), "model.env names or values") {
		t.Fatalf("compareHeader = %v; want a refusal naming model.env values", err)
	}
	if again := header(7, "gemini-a"); compareHeader(a, again) != nil {
		t.Fatal("the same settings give another header")
	}
	other := header(8, "gemini-a")
	for name, v := range a {
		if other[name] == v || strings.Contains(v, "gemini") {
			t.Fatalf("header %s = %s is not keyed per user", name, v)
		}
	}
}

// Regression (v0.4 release pentest P4): the deadline phase persists its
// scan time while no other step is recorded, so a run killed in a sandbox
// build or PoC run cannot get that time back on resume; once stopped,
// nothing more is written.
func TestKeepTimePersistsScanTime(t *testing.T) {
	s := resumedSession(t, 7, nil)
	start := time.Now()
	s.deps.sandbox.now = func() time.Time { return start.Add(90 * time.Second) }
	s.resume.scanStart = start
	stop := s.keepTime(time.Millisecond)
	deadline := time.Now().Add(5 * time.Second)
	for s.run.Summary().Elapsed < 90*time.Second {
		if time.Now().After(deadline) {
			stop()
			t.Fatalf("no time step after 5 s: %v", s.run.Summary().Steps)
		}
		time.Sleep(time.Millisecond)
	}
	stop()
	steps := len(s.run.Summary().Steps)
	time.Sleep(20 * time.Millisecond)
	if after := s.run.Summary().Steps; len(after) != steps || !strings.HasPrefix(after[0], state.StepTime) {
		t.Fatalf("steps %v after stop; want only time steps, none after stop", after)
	}
}
