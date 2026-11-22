package sandbox

import (
	"fmt"
	"path"
	"regexp"
	"slices"
	"strings"
)

// BuildReason says why the app was not built: a closed set of IDs, safe to
// print and to put in a report. Every one means verification unavailable;
// none fails the scan.
type BuildReason string

// Build reasons.
const (
	BuildNoFile            BuildReason = "no_build_file"      // no compose file or Dockerfile at the root
	BuildComposeRefused    BuildReason = "compose_refused"    // the compose file asks for something the sandbox does not allow
	BuildDockerfileRefused BuildReason = "dockerfile_refused" // the Dockerfile would reach a network or an image creep cannot check
	BuildContextRefused    BuildReason = "context_refused"    // the build context is too large or a file could not be read
	BuildBaseImageMissing  BuildReason = "base_image_missing" // a base image is not present locally; creep never pulls
	BuildFailed            BuildReason = "build_failed"       // the build ran and failed
	BuildTimeout           BuildReason = "build_timeout"      // the build ran past its time
	BuildImageRefused      BuildReason = "image_refused"      // the built image declares a VOLUME
	BuildRuntimeError      BuildReason = "runtime_error"      // the runtime CLI did not start or answer
)

// BuildReasons lists every BuildReason, so the report's closed set can be
// checked against it (report may not import sandbox).
func BuildReasons() []BuildReason {
	return []BuildReason{
		BuildNoFile, BuildComposeRefused, BuildDockerfileRefused, BuildContextRefused, BuildBaseImageMissing,
		BuildFailed, BuildTimeout, BuildImageRefused, BuildRuntimeError,
	}
}

// Repo is the scanned repository as the scan sees it: its regular files,
// as clean slash-separated paths relative to the root, and the scan's own
// reader for them (TB1), which confines reads to the root, opens without
// blocking and caps each file.
type Repo struct {
	Paths []string
	Read  func(path string) ([]byte, error)
}

// buildPlan is what the repository asks to build.
type buildPlan struct {
	context    string   // directory, relative to the root ("." for the root)
	dockerfile string   // the Dockerfile, relative to the root
	target     string   // stage to build; "" for the last
	images     []string // images the Dockerfile reads, which must be present
	checked    []byte   // the Dockerfile as checkDockerfile read it
}

// Root build files, in the order they are looked for. A compose file
// names the Dockerfile; without one, a root Dockerfile (or Podman's
// Containerfile) is built with the root as its context.
var (
	composeFiles    = []string{"compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml"}
	dockerfileNames = []string{"Dockerfile", "Containerfile"}
)

// maxBuildFileBytes bounds a compose file or Dockerfile.
const maxBuildFileBytes = 256 << 10

var stageName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// refusal is why planning stopped: a reason and a closed detail.
type refusal struct {
	reason BuildReason
	detail string
}

func refuse(reason BuildReason, detail string) *refusal {
	return &refusal{reason: reason, detail: detail}
}

// planBuild picks the build file from the repository root and checks it.
// Only files the repository provides are used: creep never writes a
// Dockerfile.
func planBuild(repo Repo) (buildPlan, *refusal) {
	paths := cleanPaths(repo.Paths)
	for _, name := range composeFiles {
		if slices.Contains(paths, name) {
			return planCompose(repo, paths, name)
		}
	}
	for _, name := range dockerfileNames {
		if slices.Contains(paths, name) {
			return planDockerfile(repo, buildPlan{context: ".", dockerfile: name})
		}
	}
	return buildPlan{}, refuse(BuildNoFile, "")
}

// planCompose takes the one service with a build section. A compose file
// without one falls back to a root Dockerfile.
func planCompose(repo Repo, paths []string, name string) (buildPlan, *refusal) {
	data, why := readBuildFile(repo, name, BuildComposeRefused)
	if why != nil {
		return buildPlan{}, why
	}
	plan, found, why := composeBuild(data)
	if why != nil {
		return buildPlan{}, why
	}
	if found {
		if !slices.Contains(paths, plan.dockerfile) {
			return buildPlan{}, refuse(BuildComposeRefused, "dockerfile_not_in_repository")
		}
		return planDockerfile(repo, plan)
	}
	for _, df := range dockerfileNames {
		if slices.Contains(paths, df) {
			return planDockerfile(repo, buildPlan{context: ".", dockerfile: df})
		}
	}
	return buildPlan{}, refuse(BuildNoFile, "compose_without_build")
}

// planDockerfile reads and checks the Dockerfile, and records the images it
// needs present.
func planDockerfile(repo Repo, plan buildPlan) (buildPlan, *refusal) {
	// Buildah (Podman) runs cpp(1) over a Dockerfile named *.in: a #define
	// the check reads as a comment rewrites the checked lines (ADD SRC
	// becomes a remote ADD), and #include reads host files.
	if strings.HasSuffix(strings.ToLower(plan.dockerfile), ".in") {
		return buildPlan{}, refuse(BuildDockerfileRefused, "preprocessed")
	}
	data, why := readBuildFile(repo, plan.dockerfile, BuildDockerfileRefused)
	if why != nil {
		return buildPlan{}, why
	}
	images, stages, rule := checkDockerfile(data)
	if rule != "" {
		return buildPlan{}, refuse(BuildDockerfileRefused, rule)
	}
	if plan.target != "" && !slices.Contains(stages, strings.ToLower(plan.target)) {
		return buildPlan{}, refuse(BuildComposeRefused, "build.target")
	}
	plan.images, plan.checked = images, data
	return plan, nil
}

func readBuildFile(repo Repo, name string, reason BuildReason) ([]byte, *refusal) {
	if repo.Read == nil {
		return nil, refuse(reason, "unreadable")
	}
	data, err := repo.Read(name)
	switch {
	case err != nil:
		return nil, refuse(reason, "unreadable")
	case len(data) > maxBuildFileBytes:
		return nil, refuse(reason, "too_large")
	}
	return data, nil
}

// within turns a compose path, relative to base, into a clean path inside
// base, or refuses it: absolute, leaving base, with a backslash, a colon
// (a drive, a URL or a git remote), a variable or a NUL.
func within(base, p string) (string, error) {
	switch {
	case p == "" || strings.ContainsAny(p, "$\\:\x00") || strings.HasPrefix(p, "git@"):
		return "", fmt.Errorf("path %q is not a repository path", p)
	case strings.HasPrefix(p, "/"):
		return "", fmt.Errorf("path %q is absolute", p)
	}
	joined := path.Join(base, p)
	if base != "." && joined != base && !strings.HasPrefix(joined, base+"/") {
		return "", fmt.Errorf("path %q leaves %q", p, base)
	}
	if joined == ".." || strings.HasPrefix(joined, "../") {
		return "", fmt.Errorf("path %q leaves the repository", p)
	}
	return joined, nil
}
