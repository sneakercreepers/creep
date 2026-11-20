package gateway

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// scriptedDial records every address asked for. Addresses in open connect
// to an in-memory pipe; the rest fail at once, or hang until the context
// ends when blackhole is set.
type scriptedDial struct {
	mu        sync.Mutex
	open      map[string]bool
	blackhole bool
	addrs     []string
}

func (d *scriptedDial) dial(ctx context.Context, _, addr string) (net.Conn, error) {
	d.mu.Lock()
	d.addrs = append(d.addrs, addr)
	d.mu.Unlock()
	if d.open[addr] {
		client, server := net.Pipe()
		_ = server.Close()
		return client, nil
	}
	if d.blackhole {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return nil, errors.New("connection refused")
}

func (d *scriptedDial) dialed() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.addrs...)
}

func scriptedDialer(t *testing.T, allow []string, res Resolver, d *scriptedDial, limits timeLimits) *pinningDialer {
	t.Helper()
	a, err := parseAllowlist(allow)
	if err != nil {
		t.Fatal(err)
	}
	return newPinningDialer(a, res, d.dial, limits)
}

// manyAddrs returns n public addresses, with last as the final one.
func manyAddrs(n int, last string) []netip.Addr {
	out := make([]netip.Addr, 0, n)
	for i := 1; i < n; i++ {
		out = append(out, netip.MustParseAddr(fmt.Sprintf("93.184.216.%d", i)))
	}
	return append(out, netip.MustParseAddr(last))
}

// Acceptance: the first dial of a host is bounded in total time and tries at
// most maxPinnedAddrs addresses, however many DNS returns; every address is
// still checked before the answer is cut.
func TestFirstDialBounded(t *testing.T) {
	tests := []struct {
		name       string
		answer     []netip.Addr
		blackhole  bool
		wantDials  int
		wantPublic bool
	}{
		{"20 black-holed addresses", manyAddrs(20, "93.184.216.200"), true, 1, true},
		{"20 refusing addresses", manyAddrs(20, "93.184.216.200"), false, maxPinnedAddrs, true},
		{"private address past the cap", manyAddrs(20, "10.0.0.1"), false, 0, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := &fakeResolver{answers: map[string][][]netip.Addr{"api.example": {tc.answer}}, calls: map[string]int{}}
			d := &scriptedDial{blackhole: tc.blackhole}
			pd := scriptedDialer(t, []string{"api.example"}, res, d, timeLimits{dialAll: 100 * time.Millisecond})
			start := time.Now()
			_, err := pd.DialContext(context.Background(), "tcp", "api.example:443")
			if err == nil {
				t.Fatal("dial succeeded, want failure")
			}
			if took := time.Since(start); took > 3*time.Second {
				t.Errorf("dial took %v, want it bounded by the dial deadline", took)
			}
			if got := len(d.dialed()); got != tc.wantDials {
				t.Errorf("dialed %d addresses, want %d", got, tc.wantDials)
			}
			if !tc.wantPublic && !errors.Is(err, ErrPrivateAddress) {
				t.Errorf("err = %v, want ErrPrivateAddress", err)
			}
		})
	}
}

// ctxResolver blocks every lookup until its context ends.
type ctxResolver struct{}

func (ctxResolver) LookupNetIP(ctx context.Context, _, _ string) ([]netip.Addr, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// A lookup that never answers is cut by the gateway's own lookup limit,
// even when the caller set no deadline.
func TestLookupBounded(t *testing.T) {
	d := &scriptedDial{}
	pd := scriptedDialer(t, []string{"api.example"}, ctxResolver{}, d, timeLimits{lookup: 50 * time.Millisecond})
	start := time.Now()
	_, err := pd.DialContext(context.Background(), "tcp", "api.example:443")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want DeadlineExceeded", err)
	}
	if took := time.Since(start); took > 3*time.Second {
		t.Errorf("lookup took %v, want it bounded", took)
	}
}

// Acceptance: a dial waiting on another dial's lookup of the same host
// returns when its own context ends.
func TestPinWaiterHonorsContext(t *testing.T) {
	res := &blockingResolver{
		fakeResolver: newResolver(map[string][]string{"slow.example": {"93.184.216.9"}}),
		slowHost:     "slow.example",
		started:      make(chan struct{}, 2),
		release:      make(chan struct{}),
	}
	pd := newDialer(t, []string{"slow.example"}, res, &recordingDial{target: "127.0.0.1:1"})
	first := make(chan struct{})
	go func() {
		_, _ = pd.DialContext(context.Background(), "tcp", "slow.example:443")
		close(first)
	}()
	<-res.started

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := pd.DialContext(ctx, "tcp", "slow.example:443")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want DeadlineExceeded", err)
	}
	if took := time.Since(start); took > 3*time.Second {
		t.Errorf("waiter took %v after its context ended", took)
	}
	close(res.release)
	<-first
}
