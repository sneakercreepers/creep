package sandbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// RunnerImage is the image PoC requests are sent from: the pinned BusyBox
// the canary uses, so the operator pulls nothing more. Its nc, timeout and
// head are the whole client; no program of the model's choosing runs.
const RunnerImage = CanaryImage

// AppHost is the app's name on the run network, the only host the runner
// connects to. A PoC never names a host: its requests reach this one.
const AppHost = appAlias

// Bounds on one Exchange.
const (
	MaxExchanges     = 4
	MaxRequestBytes  = 64 << 10
	MaxResponseBytes = 192 << 10 // MaxExchanges of them fit the 1 MiB stdout cap
	exchangeSeconds  = 20        // per request, from connect to the app closing
	readySeconds     = 30        // how long the runner waits for the app's port
	runnerTimeout    = 3 * time.Minute
	requestDir       = "/poc"
)

// ErrRunnerAnswer marks runner output that does not have the shape its
// fixed script prints. It is never read in part.
var ErrRunnerAnswer = errors.New("sandbox runner answer unreadable")

// Exchange is one request the runner sent to the app and what came back.
type Exchange struct {
	Response  []byte // the raw HTTP response, at most MaxResponseBytes
	Truncated bool   // the app sent more; the rest was dropped
	// Elapsed runs from just before the runner connected until the app
	// closed the connection, measured inside the runner (/proc/uptime, in
	// hundredths of a second), so container start-up never counts.
	Elapsed time.Duration
}

// Exchange sends each raw HTTP request, in order, to the app on port from
// one runner container on the run network. The requests are files creep
// writes in its work directory and mounts read-only; the runner's script
// is fixed, so no byte of a request reaches a command line or a shell.
// The canary runs first (RunBatch). It needs a started app (StartApp).
func (s *Sandbox) Exchange(ctx context.Context, port int, requests [][]byte) ([]Exchange, error) {
	if err := checkExchange(port, requests); err != nil {
		return nil, err
	}
	if !s.appStarted() {
		return nil, fmt.Errorf("exchange: no app on the run network: %w", ErrSpec)
	}
	mounts, err := s.writeRequests(requests)
	if err != nil {
		return nil, err
	}
	spec := Spec{Image: RunnerImage, Cmd: []string{"sh", "-c", runnerScript(port, len(requests))}, Mounts: mounts, Timeout: runnerTimeout}
	results, err := s.RunBatch(ctx, []Spec{spec})
	if err != nil {
		return nil, fmt.Errorf("exchange: %w", err)
	}
	return parseExchanges(results[0], len(requests))
}

func checkExchange(port int, requests [][]byte) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("exchange: port %d: %w", port, ErrSpec)
	}
	if len(requests) == 0 || len(requests) > MaxExchanges {
		return fmt.Errorf("exchange: %d requests outside 1..%d: %w", len(requests), MaxExchanges, ErrSpec)
	}
	for _, r := range requests {
		if len(r) == 0 || len(r) > MaxRequestBytes {
			return fmt.Errorf("exchange: request of %d bytes outside 1..%d: %w", len(r), MaxRequestBytes, ErrSpec)
		}
	}
	return nil
}

func (s *Sandbox) appStarted() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.app
}

// writeRequests writes each request as r<i> in a fresh directory of the
// work directory and mounts it at /poc/r<i>.
func (s *Sandbox) writeRequests(requests [][]byte) ([]Mount, error) {
	dir := filepath.Join(s.work, "poc-"+strconv.FormatUint(s.seq.Add(1), 10))
	if err := os.Mkdir(dir, 0o700); err != nil {
		return nil, fmt.Errorf("exchange: %w", err)
	}
	mounts := make([]Mount, 0, len(requests))
	for i, r := range requests {
		name := "r" + strconv.Itoa(i+1)
		path := filepath.Join(dir, name)
		// G306: the container user must read it; the work directory is 0700.
		if err := os.WriteFile(path, r, 0o644); err != nil { //nolint:gosec // G306, see above
			return nil, fmt.Errorf("exchange: %w", err)
		}
		mounts = append(mounts, Mount{Source: path, Target: requestDir + "/" + name})
	}
	return mounts, nil
}

// runnerScript waits for the app's port, then sends each request file to
// it and prints one line per request, "r<i> <start> <end> <bytes>", before
// any response byte, so nothing the app sends can pose as a timing line.
// The responses follow, concatenated in order. Only creep's numbers are in
// it: the port and the request count.
func runnerScript(port, n int) string {
	app := AppHost + " " + strconv.Itoa(port)
	var b strings.Builder
	b.WriteString("i=0; until nc -z -w 2 " + app + " </dev/null >/dev/null 2>&1; do i=$((i+1)); [ $i -ge " +
		strconv.Itoa(readySeconds) + " ] && break; sleep 1; done; ")
	outs := make([]string, 0, n)
	for i := 1; i <= n; i++ {
		k := strconv.Itoa(i)
		out := "/tmp/o" + k
		outs = append(outs, out)
		b.WriteString("read a _ </proc/uptime; timeout " + strconv.Itoa(exchangeSeconds) + " nc " + app +
			" <" + requestDir + "/r" + k + " 2>/dev/null | head -c " + strconv.Itoa(MaxResponseBytes+1) + " >" + out +
			"; read b _ </proc/uptime; echo \"r" + k + " $a $b $(wc -c <" + out + ")\"; ")
	}
	b.WriteString("cat " + strings.Join(outs, " "))
	return b.String()
}

// parseExchanges reads the runner's output strictly: n timing lines, then
// exactly the response bytes they announce.
func parseExchanges(res Result, n int) ([]Exchange, error) {
	if res.ExitCode != 0 || res.Truncated {
		return nil, fmt.Errorf("runner exit %d, truncated %t: %w", res.ExitCode, res.Truncated, ErrRunnerAnswer)
	}
	out := res.Output
	exchanges := make([]Exchange, n)
	sizes := make([]int, n)
	total := 0
	for i := range n {
		line, rest, ok := bytes.Cut(out, []byte("\n"))
		if !ok {
			return nil, fmt.Errorf("runner line %d missing: %w", i+1, ErrRunnerAnswer)
		}
		elapsed, size, err := parseTiming(string(line), i+1)
		if err != nil {
			return nil, err
		}
		exchanges[i].Elapsed, sizes[i], total, out = elapsed, size, total+size, rest
	}
	if len(out) != total {
		return nil, fmt.Errorf("runner sent %d response bytes, announced %d: %w", len(out), total, ErrRunnerAnswer)
	}
	for i, size := range sizes {
		exchanges[i].Response, exchanges[i].Truncated = bytes.Clone(out[:min(size, MaxResponseBytes)]), size > MaxResponseBytes
		out = out[size:]
	}
	return exchanges, nil
}

// parseTiming reads "r<i> <start> <end> <bytes>".
func parseTiming(line string, i int) (time.Duration, int, error) {
	f := strings.Fields(line)
	if len(f) != 4 || f[0] != "r"+strconv.Itoa(i) {
		return 0, 0, fmt.Errorf("runner line %d: %w", i, ErrRunnerAnswer)
	}
	start, err1 := uptime(f[1])
	end, err2 := uptime(f[2])
	size, err3 := strconv.Atoi(f[3])
	if err1 != nil || err2 != nil || err3 != nil || end < start || end-start > runnerTimeout || size < 0 || size > MaxResponseBytes+1 {
		return 0, 0, fmt.Errorf("runner line %d: %w", i, ErrRunnerAnswer)
	}
	return end - start, size, nil
}

// uptime reads one /proc/uptime value, seconds with two decimals.
func uptime(s string) (time.Duration, error) {
	whole, frac, ok := strings.Cut(s, ".")
	sec, err := strconv.ParseUint(whole, 10, 32)
	if !ok || err != nil || len(frac) != 2 || frac[0] < '0' || frac[0] > '9' || frac[1] < '0' || frac[1] > '9' {
		return 0, ErrRunnerAnswer
	}
	hundredths := int64(frac[0]-'0')*10 + int64(frac[1]-'0')
	return time.Duration(int64(sec))*time.Second + time.Duration(hundredths)*10*time.Millisecond, nil
}
