package sandbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"time"
)

// buildTimeout bounds one build. When it passes the CLI is killed, which
// ends the builder's session and cancels the build.
const buildTimeout = 15 * time.Minute

// Podman's limits for each build container, larger than the run
// profile's: installing dependencies needs more than a PoC. Docker's
// BuildKit takes no per-build limit from `docker build` (it ignores the
// legacy --memory and --cpu-* flags), and neither builder has a pids
// limit flag, so those are bounded by buildTimeout and the daemon's own
// limits only.
const (
	buildMemory    = "2g" // memory and memory+swap alike: no swap
	buildCPUPeriod = "100000"
	buildCPUQuota  = "200000" // two CPUs
)

// appAlias is the app's name on the run network.
const appAlias = "app"

var builtID = regexp.MustCompile(`^(sha256:)?([0-9a-f]{64})$`)

// App is the app image built from the repository, or why there is none.
type App struct {
	Image       string      // local image ID, sha256:<hex>; "" unless built
	Unavailable BuildReason // "" when built
	Detail      string      // closed detail of Unavailable: a compose key, a Dockerfile rule, an exit status
	workdir     string      // the image's checked working directory, set only by checkBuilt
	migrate     []string    // the app's migrate step (composeMigrate), set only by build
}

// MigrateCommand is a copy of the app's migrate step, nil without one.
func (a App) MigrateCommand() []string { return slices.Clone(a.migrate) }

// Built reports an image that StartApp can run.
func (a App) Built() bool { return a.Unavailable == "" && a.Image != "" }

func unavailable(r *refusal) App { return App{Unavailable: r.reason, Detail: r.detail} }

// Build builds the app from what the repository provides: the one service
// with a build section in its root compose file, else its root Dockerfile.
// creep never writes a Dockerfile and never runs `docker compose`. The
// build is offline: --network=none for every RUN step, no build argument,
// secret, SSH agent, extra host or entitlement, and only base images
// already present locally (creep never pulls). The one exception is the
// operator's Mirror (passed to Open, ADR 0029): on rootless Podman, after
// clearMirror, RUN steps join its internal network and get the proxy as
// build arguments; base images still never come from it. The context is
// a copy of the repository's files in the work directory, without .env
// files and credential files (stageContext).
//
// Anything that stops the build (no build file, a refused file, a missing
// base image, a failed or timed-out build, a built image that declares a
// VOLUME) is an App with Unavailable set, never an error: verification is
// then unavailable and the scan goes on. Only Ctrl+C (ErrInterrupted), the
// caller's own cancel and an aborted run return an error.
func (s *Sandbox) Build(ctx context.Context, repo Repo) (App, error) {
	if err := s.abortErr(); err != nil {
		return App{}, err
	}
	// Ctrl+C anywhere in the build, not only while the builder runs, ends
	// it with ErrInterrupted instead of killing creep, so the caller's
	// Close still removes the work directory and any built image.
	ctx, done := s.interruptible(ctx)
	defer done()
	app, err := s.build(ctx, repo)
	if err != nil && errors.Is(context.Cause(ctx), ErrInterrupted) {
		return App{}, ErrInterrupted
	}
	return app, err
}

func (s *Sandbox) build(ctx context.Context, repo Repo) (App, error) {
	plan, why := planBuild(repo)
	if why != nil {
		return unavailable(why), nil
	}
	dir, why, err := s.stageContext(ctx, repo, plan)
	if err != nil || why != nil {
		return unavailableOrErr(why, err)
	}
	dockerfile := filepath.Join(dir, filepath.FromSlash(relTo(plan.context, plan.dockerfile)))
	if info, err := os.Lstat(dockerfile); err != nil || !info.Mode().IsRegular() {
		return unavailable(refuse(BuildContextRefused, "dockerfile_left_out")), nil
	}
	// The context is a second read of the repository: the builder must get
	// the bytes that were checked, not a file changed in between.
	if staged, err := os.ReadFile(dockerfile); err != nil || !bytes.Equal(staged, plan.checked) { //nolint:gosec // G304: a file in the sandbox's own work directory
		return unavailable(refuse(BuildDockerfileRefused, "changed")), nil
	}
	if why, err := s.checkBaseImages(ctx, plan.images); err != nil || why != nil {
		return unavailableOrErr(why, err)
	}
	mirror := s.mirror
	if mirror.Set() {
		if why, err := s.clearMirror(ctx, mirror); err != nil || why != nil {
			return unavailableOrErr(why, err)
		}
	}
	image, why, err := s.runBuild(ctx, dir, dockerfile, plan.target, mirror)
	if err != nil || why != nil {
		return unavailableOrErr(why, err)
	}
	s.recordImage(image)
	app, err := s.checkBuilt(ctx, image)
	if app.Built() {
		app.migrate = plan.migrate
	}
	return app, err
}

func unavailableOrErr(why *refusal, err error) (App, error) {
	if err != nil {
		return App{}, err
	}
	return unavailable(why), nil
}

// buildArgs is the only builder of a `build` command line. Nothing in it
// comes from the repository except through the staged copy: the context
// and Dockerfile are paths in the work directory, the target a checked
// stage name. No --build-arg, --secret, --ssh, --allow, --add-host,
// --build-context, --cache-from, --output, --push or --platform is built.
// Docker's --pull=false and Podman's --pull=never keep the builder from
// pulling a newer base; Podman also gets --http-proxy=false,
// --layers=false with --force-rm so it keeps no intermediate image or
// container, and memory and CPU limits per build container. A Mirror,
// which clearMirror checked, changes only Podman's line: the operator's
// network in place of none, and the proxy build arguments (ADR 0029).
func buildArgs(st Status, runID, dir, dockerfile, target, iidfile string, m Mirror) []string {
	network, proxy := "none", []string(nil)
	if st.Runtime == Podman {
		network, proxy = mirrorArgs(m)
	}
	args := append(globalArgs(st), "build", "--quiet", "--network="+network, "--no-cache",
		"--iidfile="+iidfile, "--file="+dockerfile,
		"--label="+LabelManaged+"=true", "--label="+LabelRun+"="+runID)
	if st.Runtime == Podman {
		args = append(args, "--pull=never", "--http-proxy=false", "--layers=false", "--force-rm",
			"--memory="+buildMemory, "--memory-swap="+buildMemory,
			"--cpu-period="+buildCPUPeriod, "--cpu-quota="+buildCPUQuota)
		args = append(args, proxy...)
	} else {
		args = append(args, "--pull=false")
	}
	if target != "" {
		args = append(args, "--target="+target)
	}
	return append(args, dir)
}

// runBuild runs the build and reads the new image's ID from the iidfile
// the CLI writes, not from build output a RUN step could print.
func (s *Sandbox) runBuild(ctx context.Context, dir, dockerfile, target string, m Mirror) (string, *refusal, error) {
	iid := filepath.Join(s.work, "iid-"+strconv.FormatUint(s.seq.Add(1), 10))
	args := buildArgs(s.status, s.runID, dir, dockerfile, target, iid, m)
	buildCtx, cancel := context.WithTimeout(ctx, s.buildFor)
	defer cancel()
	res, err := s.run(buildCtx, args, outputLimit)
	switch {
	case errors.Is(context.Cause(ctx), ErrInterrupted):
		return "", nil, ErrInterrupted
	case ctx.Err() != nil:
		return "", nil, fmt.Errorf("sandbox build: %w", ctx.Err())
	case buildCtx.Err() != nil:
		return "", refuse(BuildTimeout, ""), nil
	case err != nil:
		return "", refuse(BuildRuntimeError, "start"), nil
	case res.exit != 0:
		return "", refuse(BuildFailed, "exit_"+strconv.Itoa(res.exit)), nil
	}
	id, ok := readImageID(iid)
	if !ok {
		return "", refuse(BuildFailed, "no_image_id"), nil
	}
	return id, nil, nil
}

// readImageID reads an iidfile: one image ID, with or without "sha256:".
func readImageID(path string) (string, bool) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: the iidfile in the sandbox's own work directory
	if err != nil || len(data) > 256 {
		return "", false
	}
	m := builtID.FindSubmatch(bytes.TrimSpace(data))
	if m == nil {
		return "", false
	}
	return "sha256:" + string(m[2]), true
}

// checkBuilt refuses a built image that declares a VOLUME, which Run would
// refuse too (the app could not start), or whose working directory
// checkContainerPath refuses: the image keeps its last WORKDIR, and
// StartApp runs the app there.
func (s *Sandbox) checkBuilt(ctx context.Context, image string) (App, error) {
	err := s.checkImage(ctx, Spec{Image: image})
	if err == nil {
		return s.checkWorkdir(ctx, image)
	}
	switch {
	case ctx.Err() != nil:
		return App{}, fmt.Errorf("sandbox build: %w", ctx.Err())
	case errors.Is(err, ErrImageVolumes):
		return unavailable(refuse(BuildImageRefused, "volume")), nil
	}
	return unavailable(refuse(BuildRuntimeError, "inspect")), nil
}

func (s *Sandbox) checkWorkdir(ctx context.Context, image string) (App, error) {
	dir, err := s.imageWorkdir(ctx, image)
	switch {
	case ctx.Err() != nil:
		return App{}, fmt.Errorf("sandbox build: %w", ctx.Err())
	case err != nil:
		return unavailable(refuse(BuildRuntimeError, "inspect")), nil
	}
	dir, ok := appWorkdir(dir)
	if !ok {
		return unavailable(refuse(BuildImageRefused, "workdir")), nil
	}
	return App{Image: image, workdir: dir}, nil
}

// appWorkdir is the directory the app starts in: "/" for an image without
// one, else a clean absolute path checkContainerPath accepts.
func appWorkdir(dir string) (string, bool) {
	if dir == "" {
		return "/", true
	}
	ok := path.IsAbs(dir) && path.Clean(dir) == dir && checkContainerPath(dir) == ""
	return dir, ok
}

func (s *Sandbox) recordImage(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.images = append(s.images, id)
}

// StartApp starts an image this sandbox built on the run's internal
// network as "app", detached, with the hardened profile, until Close. The
// canary runs first, as before every batch: the run phase has no route
// out. A file of fresh random content is mounted read-only at
// AppCanaryFile, for a path_payload PoC to prove a read (AppCanary), and
// the synthetic env (appEnv) reaches the run's database. One app per run.
func (s *Sandbox) StartApp(ctx context.Context, app App) error {
	workdir, err := s.checkApp(app)
	if err != nil {
		return fmt.Errorf("start app: %w", err)
	}
	if err := s.clearNetwork(ctx); err != nil {
		return err
	}
	if err := s.claimApp(); err != nil {
		return err
	}
	canary, err := s.plantCanary()
	if err != nil {
		return fmt.Errorf("start app: %w", err)
	}
	env, envFile, err := s.appEnv(workdir)
	if err != nil {
		return fmt.Errorf("start app: %w", err)
	}
	res, err := s.start(ctx, Spec{Image: app.Image, Env: env, Mounts: []Mount{canary, envFile}, networked: true, alias: appAlias, detach: true, workdir: workdir})
	if err != nil {
		return fmt.Errorf("start app: %w", err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("start app (exit %d): %w", res.ExitCode, ErrStart)
	}
	return nil
}

// checkApp returns the working directory of an image this sandbox built.
func (s *Sandbox) checkApp(app App) (string, error) {
	workdir, ok := appWorkdir(app.workdir)
	if !app.Built() || !s.builtHere(app.Image) || app.workdir == "" || !ok {
		return "", fmt.Errorf("not an image this sandbox built: %w", ErrSpec)
	}
	return workdir, nil
}

// builtImages is a copy of the IDs Build made that Close has not removed.
func (s *Sandbox) builtImages() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.images)
}

// forgetImages drops the IDs Close removed, so a second Close does not
// ask for them again.
func (s *Sandbox) forgetImages(removed []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.images = slices.DeleteFunc(s.images, func(id string) bool { return slices.Contains(removed, id) })
}

func (s *Sandbox) builtHere(image string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Contains(s.images, image)
}

func (s *Sandbox) claimApp() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.app {
		return fmt.Errorf("the run already has an app: %w", ErrSpec)
	}
	s.app = true
	return nil
}
