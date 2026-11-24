package gateway

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
)

// maxLoggedLineBytes bounds one egress.log line read back. Lines creep
// writes are a few hundred bytes; a longer one fails the open.
const maxLoggedLineBytes = 1 << 20

// loggedLine is the part of a request or result line the budget needs.
type loggedLine struct {
	Type    string `json:"type"`
	ID      string `json:"id"`
	Reserve int    `json:"reserve"`
	Tokens  *Usage `json:"tokens"`
}

// chargeLogged charges the budget with what the log already records, so a
// resumed run (#335) spends the original run's budget, not a new one: one
// call per request line, and per call its reported tokens or, without a
// report (a call cut mid-flight), its reservation, as Budget.settle keeps
// it. EndpointMaxTokens is not restored; the run limits are.
func (l *EgressLog) chargeLogged() error {
	if l.budget == nil {
		return nil
	}
	info, err := l.f.Stat()
	if err != nil {
		return fmt.Errorf("egress log: read back: %w", err)
	}
	if info.Size() == 0 {
		return nil
	}
	last := make([]byte, 1)
	if _, err := l.f.ReadAt(last, info.Size()-1); err != nil {
		return fmt.Errorf("egress log: read back: %w", err)
	}
	calls, tokens, err := loggedSpend(io.NewSectionReader(l.f, 0, info.Size()), l.budget.opts.MaxTokens, last[0] != '\n')
	if err != nil {
		return err
	}
	l.budget.charge(calls, tokens)
	return nil
}

// loggedSpend adds up a log's calls and tokens, each call's tokens capped
// at limit. Only the final line can be a torn write, when the log does not
// end in a newline (torn): its request was never sent (logRequest failed
// before the send), so it is not charged. Any other line that does not
// decode was edited or merged with a torn line before it, and may hide a
// request, so it charges a call at limit (v0.4 release pentest P6), as
// does a request line with no reservation, written before the field
// existed: an unknown spend never reads as free. Blank lines, which follow
// a torn write (EgressLog.writeLine), charge nothing.
//
// It reads the log once, line by line, with the charged map holding one
// entry per request whose result is not read yet: linear in the log's
// size and bounded by its request lines (BenchmarkLoggedSpend: about 20 ms
// for 10,000 calls on a 2019 laptop). It runs once per resume; a new run's
// log is empty.
func loggedSpend(r io.Reader, limit int, torn bool) (calls, tokens int64, err error) {
	charged := map[string]int{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4096), maxLoggedLineBytes)
	undecoded := false // the line before this one did not decode
	for sc.Scan() {
		if undecoded {
			calls, tokens = calls+1, tokens+int64(limit)
		}
		var line loggedLine
		if err := json.Unmarshal(sc.Bytes(), &line); err != nil {
			undecoded = len(sc.Bytes()) > 0
			continue
		}
		undecoded = false
		switch line.Type {
		case "request":
			c := limit
			if line.Reserve > 0 {
				c = min(line.Reserve, limit)
			}
			calls++
			tokens += int64(c)
			charged[line.ID] = c
		case "result":
			tokens += settled(charged, line, limit)
		}
	}
	if err := sc.Err(); err != nil {
		return 0, 0, fmt.Errorf("egress log: read back: %w", err)
	}
	if undecoded && !torn {
		calls, tokens = calls+1, tokens+int64(limit)
	}
	return calls, tokens, nil
}

// settled is the change a result line makes to its request's charge: the
// reported tokens replace the reservation, once per request.
func settled(charged map[string]int, line loggedLine, limit int) int64 {
	c, ok := charged[line.ID]
	u := line.Tokens
	if !ok || u == nil || u.InputTokens < 0 || u.OutputTokens < 0 {
		return 0
	}
	delete(charged, line.ID)
	return int64(spentTokens(*u, limit) - c)
}
