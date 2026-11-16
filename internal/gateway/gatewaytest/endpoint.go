package gatewaytest

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// Endpoint is a plain-HTTP model endpoint on 127.0.0.1. answer builds the
// reply body from each request body; it runs on the server goroutine.
type Endpoint struct {
	srv    *httptest.Server
	answer func(body []byte) []byte
	mu     sync.Mutex
	conns  int
	bodies [][]byte
}

// New starts an endpoint that the test's cleanup closes.
func New(tb testing.TB, answer func(body []byte) []byte) *Endpoint {
	tb.Helper()
	e := &Endpoint{answer: answer}
	e.srv = httptest.NewUnstartedServer(http.HandlerFunc(e.serve))
	e.srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			e.mu.Lock()
			e.conns++
			e.mu.Unlock()
		}
	}
	e.srv.Start()
	tb.Cleanup(e.srv.Close)
	return e
}

func (e *Endpoint) serve(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	e.mu.Lock()
	e.bodies = append(e.bodies, body)
	e.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(e.answer(body))
}

// Host is the endpoint's 127.0.0.1:port, the form egress.allow takes.
func (e *Endpoint) Host() string { return e.srv.Listener.Addr().String() }

// URL is the endpoint's base URL, http://127.0.0.1:port.
func (e *Endpoint) URL() string { return e.srv.URL }

// Conns is the number of connections the endpoint accepted.
func (e *Endpoint) Conns() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.conns
}

// Bodies returns a copy of every request body received, in order.
func (e *Endpoint) Bodies() [][]byte {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([][]byte(nil), e.bodies...)
}
