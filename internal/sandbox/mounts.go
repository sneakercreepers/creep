package sandbox

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// ErrHostPath marks a mount of the runtime's socket, another socket or
// device, or a host credential path. These never enter a container.
var ErrHostPath = errors.New("host path refused")

// ErrOutsideWorkdir marks a mount source creep did not write in the
// sandbox's work directory.
var ErrOutsideWorkdir = errors.New("mount source outside the sandbox work directory")

// refusedNames are path components that name a runtime socket or a place
// where host credentials live. Matched case-insensitively, anywhere in the
// path, before and after links are resolved.
var refusedNames = map[string]bool{
	"docker.sock": true, "podman.sock": true, "containerd.sock": true, "docker_engine": true,
	".ssh": true, ".aws": true, ".azure": true, ".kube": true, ".docker": true, ".gnupg": true,
	".netrc": true, "_netrc": true, ".git-credentials": true, ".npmrc": true, ".pypirc": true,
	"gcloud": true, "gh": true, ".creep": true, "creep": true, "credentials": true,
}

// mountArgs checks every mount and renders it read-only.
func (s *Sandbox) mountArgs(mounts []Mount) ([]string, error) {
	args := make([]string, 0, len(mounts))
	for _, m := range mounts {
		src, err := s.checkSource(m.Source)
		if err != nil {
			return nil, err
		}
		if err := checkTarget(m.Target); err != nil {
			return nil, err
		}
		args = append(args, "--mount=type=bind,source="+src+",target="+m.Target+",readonly")
	}
	return args, nil
}

// checkSource accepts only a regular file below the work directory, with
// no link, junction or special file on the way, and no refused name.
func (s *Sandbox) checkSource(src string) (string, error) {
	if hostPath(src) {
		return "", fmt.Errorf("mount %q: %w", src, ErrHostPath)
	}
	final, err := filepath.EvalSymlinks(src)
	if err != nil {
		return "", fmt.Errorf("mount %q: %w", src, err)
	}
	if hostPath(final) {
		return "", fmt.Errorf("mount %q: %w", src, ErrHostPath)
	}
	rel, err := filepath.Rel(s.workReal, final)
	if err != nil || rel == "." || !filepath.IsLocal(rel) {
		return "", fmt.Errorf("mount %q: %w", src, ErrOutsideWorkdir)
	}
	if err := plainComponents(s.workReal, rel); err != nil {
		return "", fmt.Errorf("mount %q: %w", src, err)
	}
	if strings.ContainsAny(final, ",\"\r\n\x00") {
		return "", fmt.Errorf("mount %q: unsafe character: %w", src, ErrSpec)
	}
	return final, nil
}

// plainComponents walks rel below root: every step must be a directory and
// the last a regular file. A junction (irregular on Windows), a socket, a
// pipe or a device fails.
func plainComponents(root, rel string) error {
	parts := strings.Split(rel, string(filepath.Separator))
	dir := root
	for i, part := range parts {
		dir = filepath.Join(dir, part)
		info, err := os.Lstat(dir) //nolint:gosec // G703: dir is below the work directory, checked by the caller
		if err != nil {
			return err
		}
		last := i == len(parts)-1
		if last && info.Mode().IsRegular() || !last && info.IsDir() {
			continue
		}
		return ErrHostPath
	}
	return nil
}

// hostPath reports a refused name or a socket-like path. It is defense in
// depth: sources must lie in the work directory anyway.
func hostPath(p string) bool {
	slash := filepath.ToSlash(p)
	lower := strings.ToLower(slash)
	if strings.HasPrefix(lower, "//./pipe/") || strings.HasPrefix(lower, "/var/run/") || strings.HasPrefix(lower, "/run/") {
		return true
	}
	for _, part := range strings.Split(lower, "/") {
		if refusedNames[part] || strings.HasSuffix(part, ".sock") {
			return true
		}
	}
	return false
}

// checkTarget accepts a clean absolute container path outside the kernel
// file systems and the tmpfs.
func checkTarget(t string) error {
	switch {
	case !strings.HasPrefix(t, "/") || path.Clean(t) != t || t == "/":
		return fmt.Errorf("mount target %q: not a clean absolute path: %w", t, ErrSpec)
	case len(t) > maxValueLen || strings.ContainsAny(t, ",\"\r\n\x00"):
		return fmt.Errorf("mount target %q: unsafe character: %w", t, ErrSpec)
	}
	for _, kernel := range []string{"/proc", "/sys", "/dev", "/tmp"} {
		if t == kernel || strings.HasPrefix(t, kernel+"/") {
			return fmt.Errorf("mount target %q: %w", t, ErrSpec)
		}
	}
	return nil
}
