package cli

import (
	"sync"
	"time"

	"github.com/sneakercreepers/creep/internal/state"
)

// timeEvery is how often the deadline phase persists its scan time.
const timeEvery = 15 * time.Second

// timeInterval is the deadline phase's keepTime interval.
func (d scanDeps) timeInterval() time.Duration {
	if d.timeEvery <= 0 {
		return timeEvery
	}
	return d.timeEvery
}

// keepTime persists the scan time spent every interval until the returned
// stop is called (v0.4 release pentest P4). Model calls record their time
// with their step, but a sandbox build, PoC runs, the scanners and local
// work record none, so without it a run killed there would get that time
// back on every resume. With it, a resume gets back at most one interval
// plus the call the kill cut. A write that fails is not retried: the next
// step the run records fails the run the same way (state.Run is broken).
func (s *session) keepTime(interval time.Duration) (stop func()) {
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		tick := time.NewTicker(interval)
		defer tick.Stop()
		for {
			select {
			case <-done:
				return
			case <-tick.C:
				spent := s.elapsed()
				_ = s.run.StepDoneAt(state.TimeStep(spent), spent)
			}
		}
	}()
	return func() {
		close(done)
		wg.Wait()
	}
}
