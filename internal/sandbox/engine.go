package sandbox

import (
	"context"
	"encoding/json"
	"slices"
	"strconv"
	"strings"
)

// engineVersion is major.minor.patch.
type engineVersion [3]int

// Minimum versions a runtime must report before creep starts a container
// or a build on it. Each fixes an escape the Dockerfile check cannot see,
// because it rides on a link a RUN step makes. A distribution that
// backported a fix to an older version is refused too: the version is all
// creep can check offline.
var (
	minDockerEngine = engineVersion{25, 0, 2} // vendors BuildKit 0.12.5: CVE-2024-23651, -23652, -23653
	minRunc         = engineVersion{1, 1, 12} // CVE-2024-21626: a leaked host directory as /proc/self/fd/<n>
	minBuildah      = engineVersion{1, 35, 3} // CVE-2024-1753: a bind mount's source link resolved on the host
	minCrun         = engineVersion{1, 4, 4}  // CVE-2022-27650: inheritable capabilities
	dockerRuntimes  = []string{"runc", "io.containerd.runc.v2"}
)

// parseVersion reads "1.2.3" or "1.2" with an optional "v" and any suffix
// after "-", "+", "~" or a space ("1.1.12-0ubuntu2", "v2.2.5").
func parseVersion(s string) (engineVersion, bool) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	if end := strings.IndexAny(s, "-+~ "); end >= 0 {
		s = s[:end]
	}
	parts := strings.Split(s, ".")
	if len(parts) < 2 || len(parts) > 3 {
		return engineVersion{}, false
	}
	var v engineVersion
	for i, p := range parts {
		// Six digits keep every part inside a 32-bit int.
		if p == "" || len(p) > 6 || strings.Trim(p, "0123456789") != "" {
			return engineVersion{}, false
		}
		v[i], _ = strconv.Atoi(p)
	}
	return v, true
}

func (v engineVersion) atLeast(min engineVersion) bool {
	for i := range v {
		if v[i] != min[i] {
			return v[i] > min[i]
		}
	}
	return true
}

// versionReason is ReasonOK for a version at or above min.
func versionReason(s string, min engineVersion) Reason {
	v, ok := parseVersion(s)
	switch {
	case !ok:
		return ReasonUnknownVersion
	case !v.atLeast(min):
		return ReasonOldRuntime
	}
	return ReasonOK
}

// dockerServer is the part of `docker version` the minimums read.
type dockerServer struct {
	Components []struct {
		Name    string
		Version string
	}
}

// requireDocker reads the engine's and runc's versions from `docker
// version` through the pinned endpoint. The daemon's default runtime must
// be runc, the one whose version it reports; the engine's version names
// the BuildKit it embeds, which `docker build` uses since the sandbox's
// empty DOCKER_CONFIG selects no other builder.
func requireDocker(ctx context.Context, run runFunc, host, defaultRuntime string) Reason {
	if !slices.Contains(dockerRuntimes, defaultRuntime) {
		return ReasonUnknownVersion
	}
	res, err := run(ctx, []string{"--host=" + host, "version", "--format", "{{json .Server}}"}, infoLimit)
	if err != nil || res.exit != 0 {
		return ReasonUnknownVersion
	}
	var srv dockerServer
	if res.truncated || json.Unmarshal(res.stdout, &srv) != nil {
		return ReasonUnknownVersion
	}
	if r := versionReason(component(srv, "Engine"), minDockerEngine); r != ReasonOK {
		return r
	}
	return versionReason(component(srv, "runc"), minRunc)
}

// component is the version of the one component with that name; "" when
// there is none or more than one.
func component(srv dockerServer, name string) string {
	found := ""
	for _, c := range srv.Components {
		if c.Name != name {
			continue
		}
		if found != "" {
			return ""
		}
		found = c.Version
	}
	return found
}

// requirePodman reads Buildah's and the OCI runtime's versions from
// `podman info`: runc or crun only, any other runtime is unknown.
func requirePodman(info podmanInfo) Reason {
	if r := versionReason(info.Host.BuildahVersion, minBuildah); r != ReasonOK {
		return r
	}
	version := ociVersion(info.Host.OCIRuntime.Version)
	switch info.Host.OCIRuntime.Name {
	case "runc":
		return versionReason(version, minRunc)
	case "crun":
		return versionReason(version, minCrun)
	}
	return ReasonUnknownVersion
}

// ociVersion reads "runc version 1.1.12" or "crun version 1.14.4" from
// the first line of the runtime's own version text.
func ociVersion(text string) string {
	first, _, _ := strings.Cut(text, "\n")
	f := strings.Fields(first)
	if len(f) < 3 || f[1] != "version" {
		return ""
	}
	return f[2]
}
