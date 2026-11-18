package gateway

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

// dripHandler sends the headers and then one byte every interval for n
// bytes, or until the client goes away when n is negative.
func dripHandler(interval time.Duration, n int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		flusher := w.(http.Flusher)
		w.WriteHeader(http.StatusOK)
		flusher.Flush()
		tick := time.NewTicker(interval)
		defer tick.Stop()
		for i := 0; n < 0 || i < n; i++ {
			select {
			case <-r.Context().Done():
				return
			case <-tick.C:
			}
			if _, err := w.Write([]byte("x")); err != nil {
				return
			}
			flusher.Flush()
		}
	})
}

// Acceptance: a response that stalls or trickles after its headers fails
// within a bounded time, while a body that keeps streaming completes.
func TestSlowBodyBounded(t *testing.T) {
	tests := []struct {
		name    string
		handler http.Handler
		limits  timeLimits
		wantErr error
	}{
		{"silent after headers", dripHandler(time.Hour, -1), timeLimits{bodyIdle: 100 * time.Millisecond, bodyTotal: time.Minute}, ErrResponseStalled},
		{"trickle under the idle limit", dripHandler(20*time.Millisecond, -1), timeLimits{bodyIdle: 200 * time.Millisecond, bodyTotal: 300 * time.Millisecond}, ErrResponseStalled},
		{"steady stream", dripHandler(20*time.Millisecond, 10), timeLimits{bodyIdle: 500 * time.Millisecond, bodyTotal: time.Minute}, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv, roots := newTLSServer(t, tc.handler)
			port := serverPort(t, srv)
			res := newResolver(map[string][]string{"example.com": {"198.51.100.7"}})
			d := &recordingDial{target: srv.Listener.Addr().String()}
			c := newTestClient(t, Options{Allow: []string{"example.com:" + port}, Resolver: res, Dial: d.dial, RootCAs: roots, limits: tc.limits})
			t.Cleanup(c.CloseIdleConnections)

			start := time.Now()
			body, err := get(c, "https://example.com:"+port+"/")
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if took := time.Since(start); took > 5*time.Second {
				t.Errorf("read took %v, want it bounded", took)
			}
			if tc.wantErr == nil && body != strings.Repeat("x", 10) {
				t.Errorf("body = %q, want 10 bytes", body)
			}
		})
	}
}
