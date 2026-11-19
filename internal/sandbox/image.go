package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

// ErrImageVolumes refuses an image that declares a VOLUME: the runtime
// would give each one a writable anonymous volume on the host, which
// --read-only does not cover.
var ErrImageVolumes = errors.New("sandbox image declares volumes")

// imageInfoLimit bounds the inspect answer; a volume list larger than this
// is refused, not read in part.
const imageInfoLimit = 64 << 10

// checkImage asks the runtime for the image's declared volumes and refuses
// any. The image is pinned by digest, so the image inspected is the one
// that runs. Anything but a JSON object or null fails closed.
func (s *Sandbox) checkImage(ctx context.Context, image string) error {
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	args := append(s.global(), "image", "inspect", "--format", "{{json .Config.Volumes}}", image)
	res, err := s.run(ctx, args, imageInfoLimit)
	if err != nil || res.exit != 0 || res.truncated {
		return fmt.Errorf("inspect image (exit %d): %w", res.exit, ErrStart)
	}
	var volumes map[string]json.RawMessage
	if err := json.Unmarshal(bytes.TrimSpace(res.stdout), &volumes); err != nil {
		return fmt.Errorf("inspect image: %w: %w", ErrStart, err)
	}
	if len(volumes) > 0 {
		return fmt.Errorf("%d declared: %w", len(volumes), ErrImageVolumes)
	}
	return nil
}
