package gateway

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"
)

func newDialer(t *testing.T, allow []string, res Resolver, d *recordingDial) *pinningDialer {
	t.Helper()
	a, err := parseAllowlist(allow)
	if err != nil {
		t.Fatal(err)
	}
	return newPinningDialer(a, res, d.dial, timeLimits{})
}

// The dialer repeats the allowlist check, so a transport path that skipped
// the guard still could not reach an unlisted host or port.
func TestDialContextChecksAllowlist(t *testing.T) {
	tests := []string{
		"evil.example:443",
		"api.example.com:8443",
		"10.0.0.5:443",
		"localhost:80",
	}
	for _, addr := range tests {
		res := newResolver(map[string][]string{"evil.example": {"93.184.216.7"}, "api.example.com": {"93.184.216.7"}})
		d := &recordingDial{target: "127.0.0.1:1"}
		pd := newDialer(t, []string{"api.example.com", "10.0.0.5:8443"}, res, d)
		if _, err := pd.DialContext(context.Background(), "tcp", addr); !errors.Is(err, ErrNotAllowed) {
			t.Errorf("dial %s: err = %v, want ErrNotAllowed", addr, err)
		}
		if res.total() != 0 || len(d.dialed()) != 0 {
			t.Errorf("dial %s: %d lookups, dials %v; want none", addr, res.total(), d.dialed())
		}
	}
}

// An allowlisted IP literal is dialed as is, without a lookup.
func TestDialContextIPLiteral(t *testing.T) {
	res := newResolver(nil)
	d := &recordingDial{target: "127.0.0.1:1"}
	pd := newDialer(t, []string{"10.0.0.5:8443"}, res, d)
	_, _ = pd.DialContext(context.Background(), "tcp", "10.0.0.5:8443")
	if got := d.dialed(); len(got) != 1 || got[0] != "10.0.0.5:8443" {
		t.Errorf("dialed %v, want [10.0.0.5:8443]", got)
	}
	if res.total() != 0 {
		t.Error("IP literal was resolved")
	}
}

// blockingResolver holds lookups of slowHost until release is closed.
type blockingResolver struct {
	*fakeResolver
	slowHost string
	started  chan struct{}
	release  chan struct{}
}

func (r *blockingResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	if strings.TrimSuffix(host, ".") == r.slowHost {
		r.started <- struct{}{}
		<-r.release
	}
	return r.fakeResolver.LookupNetIP(ctx, network, host)
}

// A slow lookup stalls only its own host: dials to an already pinned host
// proceed, and concurrent first dials to the slow host share one lookup.
func TestSlowLookupDoesNotBlockOtherHosts(t *testing.T) {
	res := &blockingResolver{
		fakeResolver: newResolver(map[string][]string{"fast.example": {"93.184.216.7"}, "slow.example": {"93.184.216.9"}}),
		slowHost:     "slow.example",
		started:      make(chan struct{}, 2),
		release:      make(chan struct{}),
	}
	d := &recordingDial{target: "127.0.0.1:1"}
	pd := newDialer(t, []string{"fast.example", "slow.example"}, res, d)
	ctx := context.Background()
	_, _ = pd.DialContext(ctx, "tcp", "fast.example:443")

	done := make(chan struct{}, 2)
	for i := 0; i < 2; i++ {
		go func() {
			_, _ = pd.DialContext(ctx, "tcp", "slow.example:443")
			done <- struct{}{}
		}()
	}
	<-res.started

	fast := make(chan struct{})
	go func() {
		_, _ = pd.DialContext(ctx, "tcp", "fast.example:443")
		close(fast)
	}()
	select {
	case <-fast:
	case <-time.After(5 * time.Second):
		t.Fatal("dial to a pinned host waited for another host's lookup")
	}
	close(res.release)
	<-done
	<-done
	if n := res.calls["slow.example"]; n != 1 {
		t.Errorf("slow.example resolved %d times, want 1", n)
	}
}

// Acceptance (#111): the resolver gets a fully qualified name for a
// multi-label host, so search domains cannot expand it, while the allowlist
// and the pin keep the form without the dot: both spellings share one
// lookup.
func TestLookupIsFullyQualified(t *testing.T) {
	tests := []struct {
		name      string
		host      string
		dials     []string
		wantNames []string
	}{
		{"multi-label", "api.example.com", []string{"api.example.com:443"}, []string{"api.example.com."}},
		{"trailing dot is not doubled", "api.example.com", []string{"api.example.com.:443"}, []string{"api.example.com."}},
		{"case is normalized first", "api.example.com", []string{"API.Example.COM:443"}, []string{"api.example.com."}},
		{"one pin for both spellings", "api.example.com", []string{"api.example.com:443", "api.example.com.:443"}, []string{"api.example.com."}},
		{"single label stays relative", "ollama", []string{"ollama:443"}, []string{"ollama"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := newResolver(map[string][]string{tc.host: {"93.184.216.7"}})
			d := &scriptedDial{open: map[string]bool{"93.184.216.7:443": true}}
			pd := scriptedDialer(t, []string{tc.host}, res, d, timeLimits{})
			for _, addr := range tc.dials {
				conn, err := pd.DialContext(context.Background(), "tcp", addr)
				if err != nil {
					t.Fatalf("dial %s: %v", addr, err)
				}
				_ = conn.Close()
			}
			if !slices.Equal(res.names, tc.wantNames) {
				t.Errorf("resolver received %q, want %q", res.names, tc.wantNames)
			}
		})
	}
}
