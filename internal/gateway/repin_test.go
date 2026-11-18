package gateway

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"
)

// Acceptance: after every pinned address fails, the next dial resolves
// again, and the new answer passes the same public-address check, so a
// rebinding to a private address is still refused.
func TestRepinAfterAllPinnedFail(t *testing.T) {
	tests := []struct {
		name      string
		second    string
		wantErr   error
		wantDials []string
	}{
		{"provider moved to a new public address", "198.51.100.9", nil, []string{"198.51.100.7:443", "198.51.100.9:443"}},
		{"rebinding to a private address", "10.0.0.1", ErrPrivateAddress, []string{"198.51.100.7:443"}},
		{"rebinding to loopback", "127.0.0.1", ErrPrivateAddress, []string{"198.51.100.7:443"}},
		{"rebinding to cloud metadata", "169.254.169.254", ErrPrivateAddress, []string{"198.51.100.7:443"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := newResolver(map[string][]string{"api.example": {"198.51.100.7", tc.second}})
			d := &scriptedDial{open: map[string]bool{"198.51.100.9:443": true}}
			pd := scriptedDialer(t, []string{"api.example"}, res, d, timeLimits{})
			if _, err := pd.DialContext(context.Background(), "tcp", "api.example:443"); err == nil {
				t.Fatal("first dial succeeded, want the pinned address to fail")
			}
			conn, err := pd.DialContext(context.Background(), "tcp", "api.example:443")
			if conn != nil {
				_ = conn.Close()
			}
			if !errors.Is(err, tc.wantErr) || (tc.wantErr == nil && err != nil) {
				t.Errorf("second dial err = %v, want %v", err, tc.wantErr)
			}
			if n := res.calls["api.example"]; n != 2 {
				t.Errorf("resolved %d times, want 2", n)
			}
			if got := d.dialed(); !slices.Equal(got, tc.wantDials) {
				t.Errorf("dialed %v, want %v", got, tc.wantDials)
			}
		})
	}
}

// A dial that fails because its caller gave up keeps the pin: only a
// failure of the addresses themselves makes the next dial resolve again.
func TestPinKeptWhenCallerCancels(t *testing.T) {
	res := newResolver(map[string][]string{"api.example": {"198.51.100.7", "198.51.100.9"}})
	d := &scriptedDial{blackhole: true}
	pd := scriptedDialer(t, []string{"api.example"}, res, d, timeLimits{})
	for i := 0; i < 2; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		_, err := pd.DialContext(ctx, "tcp", "api.example:443")
		cancel()
		if err == nil {
			t.Fatalf("dial %d succeeded, want failure", i)
		}
	}
	if n := res.calls["api.example"]; n != 1 {
		t.Errorf("resolved %d times, want 1", n)
	}
}

// cancelAwareResolver fails a lookup whose context has already ended.
type cancelAwareResolver struct{ *fakeResolver }

func (r cancelAwareResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return r.fakeResolver.LookupNetIP(ctx, network, host)
}

// A lookup that failed on the resolving dial's own context is not shared:
// a waiter with time left resolves again instead of failing with it.
func TestFailedLookupNotShared(t *testing.T) {
	res := cancelAwareResolver{newResolver(map[string][]string{"api.example": {"198.51.100.7"}})}
	d := &scriptedDial{open: map[string]bool{"198.51.100.7:443": true}}
	pd := scriptedDialer(t, []string{"api.example"}, res, d, timeLimits{})
	p, owner := pd.claim("api.example")
	if !owner {
		t.Fatal("first claim did not own the pin")
	}
	done := make(chan error, 1)
	go func() {
		conn, err := pd.DialContext(context.Background(), "tcp", "api.example:443")
		if conn != nil {
			_ = conn.Close()
		}
		done <- err
	}()
	time.Sleep(20 * time.Millisecond) // let the waiter block on the pin
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := pd.fill(canceled, "api.example", p); !errors.Is(err, context.Canceled) {
		t.Fatalf("owner err = %v, want Canceled", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("waiter err = %v, want it to resolve again and connect", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("waiter never returned")
	}
}
