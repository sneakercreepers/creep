package sandbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"
)

// Bounds on one cleanup: IDs per rm call and containers listed.
const (
	removeBatch   = 100
	maxContainers = 10_000
	goneChecks    = 10
	goneWait      = 500 * time.Millisecond
)

// ErrNotReachable marks a runtime creep clean cannot talk to.
var ErrNotReachable = errors.New("sandbox runtime not reachable")

var containerID = regexp.MustCompile(`^[0-9a-f]{12,64}$`)

// Removed counts what Clean removed.
type Removed struct {
	Containers int
	Networks   int
}

// Clean removes every container labeled as creep's on st, running or not,
// from this run or one that was killed, then every creep network, and
// returns how many of each it removed. Do not run it while another creep
// run uses the sandbox: it removes that run's containers and network too.
func Clean(ctx context.Context, st Status) (Removed, error) {
	if !st.Reachable || st.Path == "" {
		return Removed{}, fmt.Errorf("clean %s (%s): %w", st.Runtime, st.Reason, ErrNotReachable)
	}
	ctx, cancel := context.WithTimeout(ctx, cleanupTimeout)
	defer cancel()
	run := newExecRunner(st.Path, st.env)
	var r Removed
	var err error
	if r.Containers, err = removeLabeled(ctx, run, st, LabelManaged+"=true"); err != nil {
		return r, err
	}
	r.Networks, err = removeNetworks(ctx, run, st, LabelManaged+"=true")
	return r, err
}

// removeLabeled lists the containers carrying every label (key=value; the
// runtime ANDs the filters) and force-removes them in batches. A failed
// removal counts as done when a second listing finds none left: a --rm
// container that exits while rm stops it is removed by the runtime's own
// cleanup, and Podman's rm then fails (exit 125) on a container that is
// already going.
func removeLabeled(ctx context.Context, run runFunc, st Status, labels ...string) (int, error) {
	ids, err := listLabeled(ctx, run, st, labels)
	if err != nil {
		return 0, err
	}
	for start := 0; start < len(ids); start += removeBatch {
		batch := ids[start:min(start+removeBatch, len(ids))]
		if err := removeIDs(ctx, run, st, batch); err != nil {
			if goneSoon(ctx, run, st, labels) {
				return len(ids), nil
			}
			return start, err
		}
	}
	return len(ids), nil
}

// goneSoon reports whether no labeled container is left within a few
// seconds, while the runtime finishes its own removal.
func goneSoon(ctx context.Context, run runFunc, st Status, labels []string) bool {
	for range goneChecks {
		if left, err := listLabeled(ctx, run, st, labels); err == nil && len(left) == 0 {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(goneWait):
		}
	}
	return false
}

func listLabeled(ctx context.Context, run runFunc, st Status, labels []string) ([]string, error) {
	list := append(globalArgs(st), "ps", "--all", "--quiet", "--no-trunc")
	for _, l := range labels {
		list = append(list, "--filter", "label="+l)
	}
	res, err := run(ctx, list, infoLimit)
	if err != nil {
		return nil, fmt.Errorf("list %s containers: %w", st.Runtime, err)
	}
	if res.exit != 0 {
		return nil, fmt.Errorf("list %s containers: exit status %d", st.Runtime, res.exit)
	}
	ids, err := parseIDs(res.stdout, res.truncated)
	if err != nil {
		return nil, fmt.Errorf("list %s containers: %w", st.Runtime, err)
	}
	return ids, nil
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
