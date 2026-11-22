package gateway

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sneakercreepers/creep/internal/exitcode"
)

// A prompt nobody answers fails closed within its deadline (#116): the call
// gets a *ConsentError (exit 2) naming the timeout, a late yes is dropped,
// and the endpoint is not asked again in this run, so later calls do not
// wait again. An answer in time still counts.
func TestPromptDeadline(t *testing.T) {
	tests := []struct {
		name    string
		wait    time.Duration // the prompt deadline
		delay   time.Duration // before the prompt answers yes; -1 never answers
		granted bool
	}{
		{"never answers", 100 * time.Millisecond, -1, false},
		{"answers too late", 100 * time.Millisecond, time.Second, false},
		// A long deadline, so a loaded machine cannot turn a prompt that
		// answers at once into a timeout.
		{"answers in time", time.Minute, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			release := make(chan struct{})
			t.Cleanup(func() { close(release) })
			var asked atomic.Int32
			prompt := func(string) (bool, error) {
				asked.Add(1)
				if tt.delay < 0 {
					<-release
				}
				time.Sleep(tt.delay)
				return true, nil
			}
			c := newConsent(t, ConsentOptions{Prompt: prompt})
			c.promptWait = tt.wait
			start := time.Now()
			err := c.check(mustURL(t, "https://a.example/"))
			if elapsed := time.Since(start); elapsed > 5*time.Second {
				t.Fatalf("check took %v; want it bounded by the deadline", elapsed)
			}
			checkDeadlineResult(t, err, tt.granted)
			_ = c.check(mustURL(t, "https://a.example/"))
			if n := asked.Load(); n != 1 {
				t.Fatalf("prompted %d times; want once per run", n)
			}
		})
	}
}

func checkDeadlineResult(t *testing.T, err error, granted bool) {
	t.Helper()
	if granted {
		if err != nil {
			t.Fatalf("check = %v; want an answer in time to count", err)
		}
		return
	}
	var ce *ConsentError
	if !errors.As(err, &ce) || ce.ExitCode() != exitcode.ConfigError || !errors.Is(err, errPromptTimeout) {
		t.Fatalf("check = %v; want *ConsentError with errPromptTimeout, exit %d", err, exitcode.ConfigError)
	}
}
