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
	calls, tokens, err := loggedSpend(io.NewSectionReader(l.f, 0, info.Size()), l.budget.opts.MaxTokens)
	if err != nil {
		return err
	}
	l.budget.charge(calls, tokens)
	return nil
}

// loggedSpend adds up a log's calls and tokens, each call's tokens capped
// at limit. A line that does not decode is a torn write: its request was
// never sent (logRequest failed before the send), so it is not charged. A
// request line with no reservation, written before the field existed,
// charges limit: an unknown spend never reads as free.
func loggedSpend(r io.Reader, limit int) (calls, tokens int64, err error) {
	charged := map[string]int{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4096), maxLoggedLineBytes)
	for sc.Scan() {
		var line loggedLine
		if json.Unmarshal(sc.Bytes(), &line) != nil {
			continue
		}
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
