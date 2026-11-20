package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// ErrImageVolumes refuses an image that declares a VOLUME: the runtime
// would give each one a writable anonymous volume on the host, which
// --read-only does not cover.
var ErrImageVolumes = errors.New("sandbox image declares volumes")

// imageInfoLimit bounds the inspect answer; a volume list larger than this
// is refused, not read in part.
const imageInfoLimit = 64 << 10

// checkImage asks the runtime for the image's declared volumes and refuses
// any that no tmpfs of the spec covers: a mount at the same path replaces
// the anonymous volume, so nothing lands on the host. The image is pinned
// by digest, so the image inspected is the one that runs. Anything but a
// JSON object or null fails closed.
func (s *Sandbox) checkImage(ctx context.Context, spec Spec) error {
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	args := append(s.global(), "image", "inspect", "--format", "{{json .Config.Volumes}}", spec.Image)
	res, err := s.run(ctx, args, imageInfoLimit)
	if err != nil || res.exit != 0 || res.truncated {
		return fmt.Errorf("inspect image (exit %d): %w", res.exit, ErrStart)
	}
	var volumes map[string]json.RawMessage
	if err := json.Unmarshal(bytes.TrimSpace(res.stdout), &volumes); err != nil {
		return fmt.Errorf("inspect image: %w: %w", ErrStart, err)
	}
	uncovered := 0
	for v := range volumes {
		if !slices.Contains(spec.tmpfs, v) {
			uncovered++
		}
	}
	if uncovered > 0 {
		return fmt.Errorf("%d declared, %d not covered by a tmpfs: %w", len(volumes), uncovered, ErrImageVolumes)
	}
	return nil
}

// hasOnBuild reports whether an image inspect answer holds ONBUILD
// triggers: BuildKit runs a base image's triggers in the build that uses
// it, and nothing in the Dockerfile shows them. It reads every "OnBuild"
// key at any depth, since engines nest it differently; an answer that is
// not JSON counts as having triggers.
func hasOnBuild(inspect []byte) bool {
	var v any
	if err := json.Unmarshal(bytes.TrimSpace(inspect), &v); err != nil {
		return true
	}
	return onBuildIn(v)
}

func onBuildIn(v any) bool {
	switch t := v.(type) {
	case []any:
		return slices.ContainsFunc(t, onBuildIn)
	case map[string]any:
		for k, val := range t {
			if list, ok := val.([]any); ok && strings.EqualFold(k, "OnBuild") && len(list) > 0 {
				return true
			}
			if onBuildIn(val) {
				return true
			}
		}
	}
	return false
}

// PinnedImage is one image the network and database need. creep never
// pulls: the operator pulls it by digest (creep doctor prints how).
type PinnedImage struct {
	Role    string // canary or database
	Ref     string
	Present bool
}

// Images reports whether each pinned image is present on st. It runs only
// `image inspect`; an unusable runtime reports nothing.
func Images(ctx context.Context, st Status) []PinnedImage {
	if !st.Usable() || st.Path == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	run := newExecRunner(st.Path, st.env)
	images := []PinnedImage{{Role: "canary", Ref: CanaryImage}, {Role: "database", Ref: DatabaseImage}}
	for i, img := range images {
		res, err := run(ctx, append(globalArgs(st), "image", "inspect", "--format", "{{.Id}}", img.Ref), infoLimit)
		images[i].Present = err == nil && res.exit == 0
	}
	return images
}

// PullArgs is the command that pulls ref to the same endpoint creep
// checked (Docker's --host, Podman's local engine), after the runtime name.
func PullArgs(st Status, ref string) []string {
	return append(globalArgs(st), "pull", ref)
}
