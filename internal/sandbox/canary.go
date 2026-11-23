package sandbox

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// CanaryImage is BusyBox 1.37.0 (the multi-arch index), pinned by digest.
// creep never pulls it; the operator does (creep doctor prints how).
const CanaryImage = "docker.io/library/busybox@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec"

// Errors of the network canary. Either one aborts the run for good.
var (
	ErrNetworkLeak = errors.New("sandbox network reaches outside")
	ErrCanary      = errors.New("sandbox network canary inconclusive")
)

const (
	canaryTimeout = time.Minute
	canaryPort    = "7777"
)

// canaryCheck is one thing the canary tries from inside the run's network.
// A control must succeed, so a canary whose tools or network are broken
// never reads as "blocked"; every other check must fail. Names end in a
// dot: BusyBox's nslookup tries the host's search domain first (CI runners
// have one), and on an internal network that query fails before the bare
// name is tried, so a control would fail and a probe could ask the wrong
// name.
//
// A check reads yes when its command succeeds (probe t) or, for a public
// resolver asked directly (probe a), when any DNS reply comes back:
// NXDOMAIN or SERVFAIL from 1.1.1.1 proves a packet left as surely as an
// address does, so a failing upstream cannot hide the route. The
// network's own resolver cannot be judged that way, because a resolver
// that never forwards still answers locally (Docker's says SERVFAIL on an
// internal network); the dns check only catches one that resolves, and
// threat model X10 names that limit.
type canaryCheck struct {
	key     string
	probe   string // t: the command succeeds; a: any DNS reply
	cmd     string // {alias} is the canary's own network alias
	control bool
}

var canaryChecks = []canaryCheck{
	{"control-dns", "t", "nslookup {alias}.", true},             // the network's resolver answers
	{"control-tcp", "t", "nc -w 3 {alias} " + canaryPort, true}, // a connection on the network works
	{"dns", "t", "nslookup example.com.", false},                // the resolver forwards public names
	{"dns-direct", "a", "nslookup example.com. 1.1.1.1", false}, // UDP to a public resolver
	{"tcp-1.1.1.1", "t", "nc -w 3 1.1.1.1 443", false},          // TCP to a public address
	{"tcp-8.8.8.8", "t", "nc -w 3 8.8.8.8 53", false},           // and to a second one
}

// canaryProbes defines t and a. a says yes on success or on BusyBox's
// signs of a reply: an rcode, or "Non-authoritative" before an answer.
const canaryProbes = `t() { if "$@" </dev/null >/dev/null 2>&1; then echo yes; else echo no; fi; }; ` +
	`a() { o=$("$@" </dev/null 2>&1) && { echo yes; return; }; ` +
	`case "$o" in *NXDOMAIN*|*SERVFAIL*|*REFUSED*|*Non-authoritative*) echo yes;; *) echo no;; esac; }; `

// canaryScript listens on its own port, then runs each check and prints
// key=yes or key=no, one per line. One line, so it passes plainValue.
func canaryScript(alias string) string {
	var b strings.Builder
	b.WriteString("nc -l -p " + canaryPort + " </dev/null >/dev/null 2>&1 & sleep 1; ")
	b.WriteString(canaryProbes)
	for _, c := range canaryChecks {
		b.WriteString("echo " + c.key + "=$(" + c.probe + " " + strings.ReplaceAll(c.cmd, "{alias}", alias) + "); ")
	}
	b.WriteString("exit 0")
	return b.String()
}

// canary runs the canary container on the run's network and judges what
// it saw. Each canary gets its own alias, so a canary still being removed
// cannot answer for the next one.
func (s *Sandbox) canary(ctx context.Context) error { return s.canaryOn(ctx, "") }

// canaryOn runs the canary on bridge, the operator's mirror network, or
// on the run's network when bridge is "".
func (s *Sandbox) canaryOn(ctx context.Context, bridge string) error {
	alias := "canary-" + strconv.FormatUint(s.canaries.Add(1), 10)
	res, err := s.start(ctx, Spec{
		Image: CanaryImage, Cmd: []string{"sh", "-c", canaryScript(alias)}, Timeout: canaryTimeout,
		networked: true, alias: alias, bridge: bridge,
	})
	if err != nil {
		return fmt.Errorf("network canary: %w: %w", ErrCanary, err)
	}
	if res.ExitCode != 0 || res.Truncated {
		return fmt.Errorf("network canary exit %d: %w", res.ExitCode, ErrCanary)
	}
	return judgeCanary(res.Output)
}

// judgeCanary reads the canary's lines strictly: exactly one key=yes|no
// line per check. A leak outranks a failed control; anything unexpected
// is inconclusive, which aborts the run like a leak.
func judgeCanary(out []byte) error {
	got, err := canaryLines(out)
	if err != nil {
		return err
	}
	var leaks, failed []string
	for _, c := range canaryChecks {
		switch v := got[c.key]; {
		case !c.control && v == "yes":
			leaks = append(leaks, c.key)
		case c.control && v == "no":
			failed = append(failed, c.key)
		}
	}
	if len(leaks) > 0 {
		return fmt.Errorf("canary got through (%s): %w", strings.Join(leaks, ", "), ErrNetworkLeak)
	}
	if len(failed) > 0 {
		return fmt.Errorf("canary control failed (%s): %w", strings.Join(failed, ", "), ErrCanary)
	}
	return nil
}

func canaryLines(out []byte) (map[string]string, error) {
	got := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok || (value != "yes" && value != "no") || got[key] != "" || !isCanaryKey(key) {
			return nil, fmt.Errorf("canary answer: %w", ErrCanary)
		}
		got[key] = value
	}
	if len(got) != len(canaryChecks) {
		return nil, fmt.Errorf("canary answered %d of %d checks: %w", len(got), len(canaryChecks), ErrCanary)
	}
	return got, nil
}

func isCanaryKey(key string) bool {
	for _, c := range canaryChecks {
		if c.key == key {
			return true
		}
	}
	return false
}
