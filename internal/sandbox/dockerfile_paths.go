package sandbox

import (
	"path"
	"regexp"
	"slices"
	"strings"
)

// Dockerfile rules for paths inside the build container and for image
// transports (v0.2 sandbox hardening).
const (
	ruleContainerPath = "container_path" // a WORKDIR or mount target that is not a plain path, climbs out of its directory, or lies in /proc, /sys or /dev
	ruleMountFrom     = "mount_from"     // a RUN --mount from= another stage or image: its links resolve on the host under Buildah < 1.35.3
	ruleTransport     = "transport"      // an image reference with a transport prefix (containers-storage:, docker://, oci-archive:)
)

// containerPathChars is a plain path: no variable, quote, escape or white
// space, so BuildKit's and Buildah's word expansion leave it as written.
var containerPathChars = regexp.MustCompile(`^[A-Za-z0-9._/@+=,%~-]+$`)

// kernelDirs are the pseudo-filesystems a working directory or a mount
// target must stay out of: runc < 1.1.12 leaked a host directory as
// /proc/self/fd/<n> (CVE-2024-21626), and BuildKit < 0.12.5 followed a
// mount target through links (CVE-2024-23652).
var kernelDirs = []string{"proc", "sys", "dev"}

// imageTransports are the containers/image transports Buildah reads
// before an image name (`containers-storage:alpine`), each of which skips
// the registry name the presence check reads. "docker" is left out: it
// needs "//", which "://" catches, and `docker:27` is the image docker.
var imageTransports = []string{
	"containers-storage", "dir", "docker-archive", "docker-daemon", "oci", "oci-archive", "ostree", "sif", "tarball",
}

// checkContainerPath accepts a WORKDIR or mount target only as a plain
// path that, cleaned of ".." as both builders clean it, neither climbs
// above the directory it is relative to nor starts in a kernel directory.
// A relative path starts in the previous WORKDIR, which may be "/", so
// its first element is checked as if it were absolute. A link a RUN step
// made is not seen; the minimum runc, BuildKit and Buildah versions
// (requireDocker,
// requirePodman) are the control there.
func checkContainerPath(p string) string {
	if len(p) > 1024 || !containerPathChars.MatchString(p) {
		return ruleContainerPath
	}
	clean := path.Clean(p)
	if clean == ".." || strings.HasPrefix(clean, "../") {
		return ruleContainerPath
	}
	first, _, _ := strings.Cut(strings.TrimPrefix(clean, "/"), "/")
	if slices.Contains(kernelDirs, first) {
		return ruleContainerPath
	}
	return ""
}

// hasTransport reports a reference Buildah would read through a transport
// other than a registry.
func hasTransport(ref string) bool {
	if strings.Contains(ref, "://") {
		return true
	}
	prefix, _, ok := strings.Cut(ref, ":")
	return ok && slices.Contains(imageTransports, strings.ToLower(prefix))
}
