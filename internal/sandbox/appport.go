package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// AppPort is the TCP port an image this sandbox built declares (its
// Dockerfile's EXPOSE): the lowest, so the choice never depends on the
// runtime's map order. 0 means it declares none. The port only picks
// where the runner connects on the run network: the app is the
// repository's own, and nothing is published.
func (s *Sandbox) AppPort(ctx context.Context, app App) (int, error) {
	if !app.Built() || !s.builtHere(app.Image) {
		return 0, fmt.Errorf("app port: not an image this sandbox built: %w", ErrSpec)
	}
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	args := append(s.global(), "image", "inspect", "--format", "{{json .Config.ExposedPorts}}", app.Image)
	res, err := s.run(ctx, args, imageInfoLimit)
	if err != nil || res.exit != 0 || res.truncated {
		return 0, fmt.Errorf("inspect app port (exit %d): %w", res.exit, ErrStart)
	}
	var exposed map[string]json.RawMessage
	if err := json.Unmarshal(bytes.TrimSpace(res.stdout), &exposed); err != nil {
		return 0, fmt.Errorf("inspect app port: %w: %w", ErrStart, err)
	}
	return lowestTCPPort(exposed), nil
}

// lowestTCPPort reads "<port>/tcp" keys; any other protocol, or a key
// that is not one port from 1 to 65535, is skipped.
func lowestTCPPort(exposed map[string]json.RawMessage) int {
	lowest := 0
	for key := range exposed {
		num, ok := strings.CutSuffix(key, "/tcp")
		if !ok || num == "" || len(num) > 5 || strings.TrimLeft(num, "0123456789") != "" {
			continue
		}
		port, err := strconv.Atoi(num)
		if err != nil || port < 1 || port > 65535 {
			continue
		}
		if lowest == 0 || port < lowest {
			lowest = port
		}
	}
	return lowest
}
