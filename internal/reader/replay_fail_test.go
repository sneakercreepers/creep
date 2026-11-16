package reader

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/sneakercreepers/creep/internal/models"
	"github.com/sneakercreepers/creep/internal/state"
)

func caseFor(t *testing.T, app string) appCase {
	t.Helper()
	for _, c := range appCases {
		if c.app == app {
			return c
		}
	}
	t.Fatalf("no case for %s", app)
	return appCase{}
}

// replayBoth replays both variants of c and returns the first error and
// every mismatch with expected.json.
func replayBoth(store *state.Store, mode state.Mode, tier Tier, c appCase, m model) ([]error, error) {
	var mismatches []error
	for _, variant := range []string{variantVulnerable, variantSafe} {
		got, err := runVariant(store, mode, tier, c, variant, m)
		if err != nil {
			return mismatches, err
		}
		mismatches = append(mismatches, c.mismatches(variant, got)...)
	}
	return mismatches, nil
}

func refuseModel(t *testing.T) model {
	return func(appHypothesis) ([]byte, error) {
		t.Error("replay called the model")
		return nil, errors.New("replay must not call the model")
	}
}

func openStore(t *testing.T, dir string, secret []byte) *state.Store {
	t.Helper()
	store, err := state.Open(dir, secret)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

// editFixture rewrites the first recording in cache with edit.
func editFixture(edit func([]byte) []byte) func(*testing.T, string) {
	return func(t *testing.T, dir string) {
		t.Helper()
		name := filepath.Join(dir, "cache", cacheFiles(t, dir)[0])
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(name, edit(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// A committed fixture that is missing, torn, edited, signed by another
// secret or recorded for another prompt fails the replay with the store's
// error; it never passes silently and never falls back to a model call.
func TestReplayFailsClosed(t *testing.T) {
	removeFirst := func(t *testing.T, dir string) {
		t.Helper()
		if err := os.Remove(filepath.Join(dir, "cache", cacheFiles(t, dir)[0])); err != nil {
			t.Fatal(err)
		}
	}
	tests := []struct {
		name   string
		tamper func(*testing.T, string)
		secret []byte
		tier   Tier
		want   error
	}{
		{"missing fixture", removeFirst, fixtureSecret, replayTier, state.ErrNotRecorded},
		{"torn fixture", editFixture(func(b []byte) []byte { return b[:len(b)/2] }), fixtureSecret, replayTier, state.ErrCorrupt},
		{"edited response", editFixture(func(b []byte) []byte { b[len(b)/2] ^= 1; return b }), fixtureSecret, replayTier, state.ErrCorrupt},
		{"signed with another secret", nil, bytes.Repeat([]byte{0xa5}, state.SecretBytes), replayTier, state.ErrUnauthenticated},
		{"recorded for another tier's prompt", nil, fixtureSecret, TierS, state.ErrNotRecorded},
	}
	c := caseFor(t, "flask")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := copyFixtures(t, filepath.Join(replayDir, c.app))
			if tt.tamper != nil {
				tt.tamper(t, dir)
			}
			_, err := replayBoth(openStore(t, dir, tt.secret), state.ModeReplay, tt.tier, c, refuseModel(t))
			if !errors.Is(err, tt.want) {
				t.Fatalf("replay error = %v, want %v", err, tt.want)
			}
		})
	}
}

// A validly signed recording whose answer contradicts expected.json is a
// mismatch, and one that breaks the schema or cites a line the model was
// not shown is an error: a wrong fixture can never make the test pass.
func TestReplayRejectsWrongAnswers(t *testing.T) {
	conf := 90
	answer := func(a any) model {
		return func(appHypothesis) ([]byte, error) { return chatCompletion(a) }
	}
	tests := []struct {
		name     string
		model    model
		want     error
		mismatch bool
	}{
		{"verdicts swapped", func(h appHypothesis) ([]byte, error) {
			h.variant = map[string]string{variantVulnerable: variantSafe, variantSafe: variantVulnerable}[h.variant]
			return synthesizedReply(h)
		}, nil, true},
		{"vulnerable without citing the sink", func(h appHypothesis) ([]byte, error) {
			return chatCompletion(Answer{Verdict: answerVulnerable, Evidence: []Evidence{{Start: h.source, End: h.source}}, Confidence: &conf})
		}, nil, true},
		{"inconclusive everywhere", answer(Answer{Verdict: answerInconclusive, Evidence: []Evidence{}, Confidence: &conf}), nil, true},
		{"evidence outside the slice", answer(Answer{Verdict: answerVulnerable, Evidence: []Evidence{{Start: MaxLine, End: MaxLine}}, Confidence: &conf}), ErrEvidence, false},
		{"unknown field", answer(map[string]any{"verdict": answerVulnerable, "evidence": []Evidence{{Start: 1, End: 1}}, "confidence": conf, "note": "x"}), models.ErrInvalidOutput, false},
		{"verdict outside the enum", answer(map[string]any{"verdict": "safe", "evidence": []Evidence{}, "confidence": conf}), models.ErrInvalidOutput, false},
	}
	c := caseFor(t, "flask")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			// Recording stores the reply before it is decoded, so the bad
			// answer is on disk even when the record pass fails on it.
			_, _ = replayBoth(openStore(t, dir, fixtureSecret), state.ModeRecord, replayTier, c, tt.model)
			mismatches, err := replayBoth(openStore(t, dir, fixtureSecret), state.ModeReplay, replayTier, c, refuseModel(t))
			if tt.want != nil && !errors.Is(err, tt.want) {
				t.Fatalf("replay error = %v, want %v", err, tt.want)
			}
			if tt.want == nil && err != nil {
				t.Fatalf("replay: %v", err)
			}
			if tt.mismatch != (len(mismatches) > 0) {
				t.Fatalf("mismatches = %v, want some: %t", mismatches, tt.mismatch)
			}
		})
	}
}
