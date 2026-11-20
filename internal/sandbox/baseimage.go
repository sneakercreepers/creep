package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// enginePlatform is os/arch in Go's names, as `docker version` and
// `podman info` report them.
var enginePlatform = regexp.MustCompile(`^[a-z0-9]+/[a-z0-9]+$`)

// baseInspect is the part of `image inspect` the base check reads. Docker
// shows ONBUILD triggers in Config.OnBuild; Podman's inspect has no such
// field, but its History lists the step that set each trigger.
type baseInspect struct {
	Os           string
	Architecture string
	History      []struct {
		CreatedBy string `json:"created_by"`
	}
}

// checkBaseImages makes sure every image the Dockerfile reads is present
// locally, for the engine's own platform and with no ONBUILD trigger, so
// the builder has nothing to pull and runs only what the check read.
func (s *Sandbox) checkBaseImages(ctx context.Context, images []string) (*refusal, error) {
	platform, why, err := s.platform(ctx)
	if err != nil || why != nil {
		return why, err
	}
	missing := 0
	for _, ref := range images {
		inspectCtx, cancel := context.WithTimeout(ctx, probeTimeout)
		res, err := s.run(inspectCtx, append(s.global(), "image", "inspect", ref), infoLimit)
		cancel()
		switch {
		case ctx.Err() != nil:
			return nil, fmt.Errorf("sandbox build: %w", ctx.Err())
		case err != nil:
			return refuse(BuildRuntimeError, "inspect"), nil
		case res.exit != 0:
			missing++
		default:
			if problem := baseImageProblem(res.stdout, platform); problem != "" {
				return refuse(BuildImageRefused, problem), nil
			}
		}
	}
	if missing > 0 {
		return refuse(BuildBaseImageMissing, strconv.Itoa(missing)+"_of_"+strconv.Itoa(len(images))), nil
	}
	return nil, nil
}

// platform asks the engine for its os/arch once per build, in a fixed
// format; anything else is a runtime error.
func (s *Sandbox) platform(ctx context.Context) (string, *refusal, error) {
	args := append(s.global(), "version", "--format", "{{.Server.Os}}/{{.Server.Arch}}")
	if s.status.Runtime == Podman {
		args = append(s.global(), "info", "--format", "{{.Host.OS}}/{{.Host.Arch}}")
	}
	probeCtx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	res, err := s.run(probeCtx, args, infoLimit)
	switch platform := string(bytes.TrimSpace(res.stdout)); {
	case ctx.Err() != nil:
		return "", nil, fmt.Errorf("sandbox build: %w", ctx.Err())
	case err != nil || res.exit != 0 || !enginePlatform.MatchString(platform):
		return "", refuse(BuildRuntimeError, "platform"), nil
	default:
		return platform, nil, nil
	}
}

// baseImageProblem reads one image's inspect answer: anything but exactly
// one image for platform, with no ONBUILD trigger, is refused. An answer
// that is not JSON (truncated too) is refused as having triggers.
func baseImageProblem(inspect []byte, platform string) string {
	var images []baseInspect
	if err := json.Unmarshal(bytes.TrimSpace(inspect), &images); err != nil || hasOnBuild(inspect) {
		return "base_onbuild"
	}
	if len(images) != 1 || images[0].Os+"/"+images[0].Architecture != platform {
		return "base_platform"
	}
	return ""
}

// hasOnBuild reports whether an image inspect answer holds ONBUILD
// triggers: BuildKit and buildah run a base image's triggers in the build
// that uses it, and nothing in the Dockerfile shows them. It reads every
// "OnBuild" key at any depth, since engines nest it differently, and every
// history step that set one; an answer that is not JSON counts as having
// triggers.
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
			if setsOnBuild(k, val) || onBuildIn(val) {
				return true
			}
		}
	}
	return false
}

// setsOnBuild is a non-empty OnBuild list, or a history step whose
// command set a trigger ("/bin/sh -c #(nop) ONBUILD ...").
func setsOnBuild(key string, val any) bool {
	if list, ok := val.([]any); ok && strings.EqualFold(key, "OnBuild") {
		return len(list) > 0
	}
	s, ok := val.(string)
	return ok && strings.EqualFold(key, "created_by") && strings.Contains(strings.ToUpper(s), "ONBUILD")
}
