package cli

import (
	"context"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/sneakercreepers/creep/internal/gateway"
	"github.com/sneakercreepers/creep/internal/models"
)

// Scan phases, in pipeline order. --stats prints them by these IDs.
const (
	phaseCalibrate = "calibrate"
	phaseStatic    = "static"
	phasePlan      = "plan"
	phaseRead      = "read"
	phaseReport    = "report"
)

// runStats counts what one scan spent (--stats, ADR 0011). It holds only
// phase IDs, numbers and the model's own purpose labels, never repository
// text, so printing it cannot leak or inject anything from the scan.
type runStats struct {
	now func() time.Time

	mu        sync.Mutex
	phases    []phaseTime
	requests  int // model requests the pipeline made
	sent      int // requests that reached the transport (the gateway)
	cached    int // requests served from the run-state cache
	failed    int // requests that ended in an error
	usage     gateway.Usage
	cacheUse  gateway.Usage // tokens the recorded replies report: not spent again
	noUsage   int           // sent replies that reported no token count
	byPurpose map[string]int
}

type phaseTime struct {
	name string
	took time.Duration
}

func newRunStats(now func() time.Time) *runStats {
	if now == nil {
		now = time.Now
	}
	return &runStats{now: now, byPurpose: map[string]int{}}
}

// start times a phase; the returned func records it.
func (st *runStats) start(name string) func() {
	began := st.now()
	return func() {
		took := st.now().Sub(began)
		st.mu.Lock()
		defer st.mu.Unlock()
		st.phases = append(st.phases, phaseTime{name: name, took: took})
	}
}

// sentMark is the context key the inner wrapper uses to tell the outer one
// that this request reached the transport (it was not served from cache).
type sentMark struct{}

// countRequests wraps the cached send: every request the pipeline makes.
func (st *runStats) countRequests(send models.SendFunc) models.SendFunc {
	return func(ctx context.Context, c gateway.Call) (*gateway.Reply, error) {
		sent := new(bool)
		r, err := send(context.WithValue(ctx, sentMark{}, sent), c)
		st.addRequest(c, r, err, *sent)
		return r, err
	}
}

// countSent wraps the transport: only requests the cache did not serve.
func (st *runStats) countSent(send models.SendFunc) models.SendFunc {
	return func(ctx context.Context, c gateway.Call) (*gateway.Reply, error) {
		if mark, ok := ctx.Value(sentMark{}).(*bool); ok {
			*mark = true
		}
		r, err := send(ctx, c)
		st.addSent(c, r, err)
		return r, err
	}
}

func (st *runStats) addRequest(c gateway.Call, r *gateway.Reply, err error, sent bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.requests++
	st.byPurpose[c.Purpose]++
	switch {
	case err != nil:
		st.failed++
	case !sent:
		st.cached++
		if u, ok := replyUsage(c, r); ok {
			st.cacheUse = addUsage(st.cacheUse, u)
		}
	}
}

func (st *runStats) addSent(c gateway.Call, r *gateway.Reply, err error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.sent++
	if err != nil {
		return
	}
	u, ok := replyUsage(c, r)
	if !ok {
		st.noUsage++
		return
	}
	st.usage = addUsage(st.usage, u)
}

func replyUsage(c gateway.Call, r *gateway.Reply) (gateway.Usage, bool) {
	if r == nil || c.Usage == nil {
		return gateway.Usage{}, false
	}
	return c.Usage(r.Body)
}

func addUsage(a, b gateway.Usage) gateway.Usage {
	return gateway.Usage{InputTokens: a.InputTokens + b.InputTokens, OutputTokens: a.OutputTokens + b.OutputTokens}
}

// print writes the stats block. Purpose labels are the pipeline's own
// constants; they are escaped anyway, as everything printed is.
func (st *runStats) print(w io.Writer, p pricing) {
	st.mu.Lock()
	defer st.mu.Unlock()
	fmt.Fprintln(w, "stats:")
	fmt.Fprintf(w, "  phases: %s\n", st.phaseList())
	fmt.Fprintf(w, "  model requests: %d (%d sent, %d from cache, %d failed; cache hit rate %s)\n",
		st.requests, st.sent, st.cached, st.failed, percent(st.cached, st.requests))
	if len(st.byPurpose) > 0 {
		fmt.Fprintf(w, "  by purpose: %s\n", st.purposeList())
	}
	fmt.Fprintf(w, "  tokens sent: %d in, %d out", st.usage.InputTokens, st.usage.OutputTokens)
	if st.noUsage > 0 {
		fmt.Fprintf(w, " (%d replies reported no count)", st.noUsage)
	}
	fmt.Fprintf(w, "\n  tokens served from cache: %d in, %d out\n", st.cacheUse.InputTokens, st.cacheUse.OutputTokens)
	fmt.Fprintf(w, "  cost: %s\n", p.cost(st.usage.InputTokens, st.usage.OutputTokens))
}

func (st *runStats) phaseList() string {
	parts := make([]string, len(st.phases))
	for i, ph := range st.phases {
		parts[i] = fmt.Sprintf("%s %s", ph.name, ph.took.Round(time.Millisecond))
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ", ")
}

func (st *runStats) purposeList() string {
	names := make([]string, 0, len(st.byPurpose))
	for name := range st.byPurpose {
		names = append(names, name)
	}
	slices.Sort(names)
	parts := make([]string, len(names))
	for i, name := range names {
		parts[i] = fmt.Sprintf("%s %d", escapeControl(name), st.byPurpose[name])
	}
	return strings.Join(parts, ", ")
}

// percent is part of whole as a rounded percentage, or "n/a" for none.
func percent(part, whole int) string {
	if whole == 0 {
		return "n/a"
	}
	return fmt.Sprintf("%d%%", (part*100+whole/2)/whole)
}
