package gateway

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	cutLine     = `{"v":1,"type":"request","id":"a","reserve":100}` + "\n"
	settledLine = `{"v":1,"type":"result","id":"a","outcome":"response","status":200,"tokens":{"input":5,"output":7}}` + "\n"
)

// A reopened log is a resumed run (#335): its calls and tokens count
// against the new budget, so resuming cannot reset a limit, and nothing in
// the log can make a spend read as free.
func TestReopenedLogChargesBudget(t *testing.T) {
	tests := []struct {
		name       string
		log        string
		wantCalls  int64
		wantTokens int64
	}{
		{"empty", "", 0, 0},
		{"call cut mid-flight keeps its reservation", cutLine, 1, 100},
		{"reported usage replaces the reservation", cutLine + settledLine, 1, 12},
		{"result reported twice counts once", cutLine + settledLine + settledLine, 1, 12},
		{"result without usage keeps the reservation", cutLine + `{"type":"result","id":"a","outcome":"transport"}` + "\n", 1, 100},
		{"negative usage keeps the reservation", cutLine + `{"type":"result","id":"a","tokens":{"input":-5,"output":1}}` + "\n", 1, 100},
		{"result with no request is ignored", settledLine, 0, 0},
		{"line without reservation charges the limit", `{"v":1,"type":"request","id":"b"}` + "\n", 1, 1000},
		{"reservation over the limit is capped", `{"type":"request","id":"b","reserve":5000}` + "\n", 1, 1000},
		{"torn final line is not charged", cutLine + `{"v":1,"type":"request","id":"c"`, 1, 100},
		{"blank line after a torn write is free", cutLine + "\n" + cutLine, 2, 200},
		{"undecodable line before others charges a call at the limit", `{"v":1,"type":"requ` + "\n" + cutLine, 2, 1000},
		{"undecodable final line with a newline is charged", cutLine + `{"v":1,"type":"requ` + "\n", 2, 1000},
		{"line merged with a torn one is charged", `{"v":1,"type":"requ{"v":1,"type":"request","id":"d","reserve":5}` + "\n", 1, 1000},
		{"wrongly typed field charges once", `{"v":1,"type":"request","id":"e","reserve":"lots"}` + "\n", 1, 1000},
		{"totals are capped at the limits", strings.Repeat(`{"type":"request","id":"x","reserve":900}`+"\n", 20), 9, 1000},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := runDir(t)
			writeLog(t, dir, tt.log)
			b := newBudget(t, BudgetOptions{MaxTokens: 1000, MaxCalls: 9})
			openBudgetLog(t, dir, b)
			if b.calls != tt.wantCalls || b.tokens != tt.wantTokens {
				t.Fatalf("budget after reopen = %d calls, %d tokens; want %d, %d", b.calls, b.tokens, tt.wantCalls, tt.wantTokens)
			}
		})
	}
}

// A line longer than any creep writes fails the open instead of being
// skipped, so a damaged log cannot hide the calls after it.
func TestReopenedLogOversizedLineRefused(t *testing.T) {
	dir := runDir(t)
	writeLog(t, dir, cutLine+`{"pad":"`+strings.Repeat("x", maxLoggedLineBytes)+`"}`+"\n"+cutLine)
	if _, err := OpenEgressLog(dir, allowAllConsent(t), roomyBudget(t)); err == nil || !strings.Contains(err.Error(), "read back") {
		t.Fatalf("OpenEgressLog = %v; want a read-back error", err)
	}
}

// A call cut mid-flight is sent again in full after the reopen, and the
// log keeps both attempts; the original run's spend still counts, so the
// call limit stops the run one call earlier than an uninterrupted one
// would: the cut call counts twice, once for its logged reservation and
// once when it is sent again (v0.4 review A5).
func TestReopenedLogKeepsBothAttempts(t *testing.T) {
	m := newModelServer(t, `{}`)
	dir := runDir(t)
	call := testCall(m.url("/v1"))
	first := openBudgetLog(t, dir, newBudget(t, BudgetOptions{MaxTokens: 1000, MaxCalls: 2}))
	if _, err := first.logRequest(call, m.url("/v1")); err != nil { // write-ahead line, then the process dies
		t.Fatal(err)
	}
	_ = first.Close()
	l := openBudgetLog(t, dir, newBudget(t, BudgetOptions{MaxTokens: 1000, MaxCalls: 2}))
	if _, err := l.Send(context.Background(), m.client(t), call); err != nil {
		t.Fatalf("resent call: %v", err)
	}
	_, err := l.Send(context.Background(), m.client(t), call)
	checkBudgetRefusal(t, err, LimitRunCalls)
	requests := 0
	for _, line := range readLines(t, dir) {
		if line["type"] == "request" {
			requests++
			if line["reserve"] != 100.0 {
				t.Fatalf("request line %v does not record its reservation", line)
			}
		}
	}
	if _, bodies := m.stats(); requests != 2 || len(bodies) != 1 {
		t.Fatalf("log has %d request lines, server saw %d bodies; want 2 attempts and 1 send", requests, len(bodies))
	}
}

func writeLog(t *testing.T, dir, content string) {
	t.Helper()
	if content == "" {
		return
	}
	if err := os.WriteFile(filepath.Join(dir, egressLogName), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// BenchmarkLoggedSpend backs loggedSpend's documented cost (v0.4 review
// A10): one linear read of a resumed run's log, here 10,000 calls, each a
// request line and its result line.
func BenchmarkLoggedSpend(b *testing.B) {
	var log strings.Builder
	for i := range 10000 {
		id := fmt.Sprintf("req-%d", i)
		fmt.Fprintf(&log, `{"v":1,"type":"request","id":%q,"reserve":1024}`+"\n", id)
		fmt.Fprintf(&log, `{"v":1,"type":"result","id":%q,"outcome":"response","status":200,"tokens":{"input":500,"output":200}}`+"\n", id)
	}
	data := log.String()
	b.SetBytes(int64(len(data)))
	for b.Loop() {
		if _, _, err := loggedSpend(strings.NewReader(data), 1<<20, false); err != nil {
			b.Fatal(err)
		}
	}
}
