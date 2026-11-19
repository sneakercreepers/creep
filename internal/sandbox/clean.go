package sandbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"regexp"
)

// Bounds on one cleanup: IDs per rm call and containers listed.
const (
	removeBatch   = 100
	maxContainers = 10_000
)

// ErrNotReachable marks a runtime creep clean cannot talk to.
var ErrNotReachable = errors.New("sandbox runtime not reachable")

var containerID = regexp.MustCompile(`^[0-9a-f]{12,64}$`)

// Clean removes every container labeled as creep's on st, running or not,
// from this run or one that was killed, and returns how many it removed.
// Do not run it while another creep run uses the sandbox: it removes that
// run's containers too.
func Clean(ctx context.Context, st Status) (int, error) {
	if !st.Reachable || st.Path == "" {
		return 0, fmt.Errorf("clean %s (%s): %w", st.Runtime, st.Reason, ErrNotReachable)
	}
	ctx, cancel := context.WithTimeout(ctx, cleanupTimeout)
	defer cancel()
	return removeLabeled(ctx, newExecRunner(st.Path, st.env), st, LabelManaged+"=true")
}

// removeLabeled lists the containers carrying label (key=value) and
// force-removes them in batches.
func removeLabeled(ctx context.Context, run runFunc, st Status, label string) (int, error) {
	list := append(globalArgs(st), "ps", "--all", "--quiet", "--no-trunc", "--filter", "label="+label)
	res, err := run(ctx, list, infoLimit)
	if err != nil {
		return 0, fmt.Errorf("list %s containers: %w", st.Runtime, err)
	}
	if res.exit != 0 {
		return 0, fmt.Errorf("list %s containers: exit status %d", st.Runtime, res.exit)
	}
	ids, err := parseIDs(res.stdout, res.truncated)
	if err != nil {
		return 0, fmt.Errorf("list %s containers: %w", st.Runtime, err)
	}
	for start := 0; start < len(ids); start += removeBatch {
		batch := ids[start:min(start+removeBatch, len(ids))]
		if err := removeIDs(ctx, run, st, batch); err != nil {
			return start, err
		}
	}
	return len(ids), nil
}

func removeIDs(ctx context.Context, run runFunc, st Status, ids []string) error {
	args := append(append(globalArgs(st), "rm", "--force"), ids...)
	res, err := run(ctx, args, infoLimit)
	if err != nil {
		return fmt.Errorf("remove %s containers: %w", st.Runtime, err)
	}
	if res.exit != 0 {
		return fmt.Errorf("remove %s containers: exit status %d", st.Runtime, res.exit)
	}
	return nil
}

// parseIDs accepts one hex container ID per line and nothing else, so no
// runtime output becomes an argument other than an ID.
func parseIDs(out []byte, truncated bool) ([]string, error) {
	if truncated {
		return nil, errors.New("container list too large")
	}
	var ids []string
	for _, line := range bytes.Split(out, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		if !containerID.Match(line) {
			return nil, errors.New("container list holds something that is not an ID")
		}
		if len(ids) == maxContainers {
			return nil, errors.New("too many containers")
		}
		ids = append(ids, string(line))
	}
	return ids, nil
}
