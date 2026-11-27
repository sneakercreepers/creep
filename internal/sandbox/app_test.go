package sandbox

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// TestStartAppAfterCanary: the built app runs only on the run network,
// detached, hardened and as "app", after the canary passed; only an image
// this sandbox built runs, once; a failed canary starts no app.
func TestStartAppAfterCanary(t *testing.T) {
	rec := withBuilds(networkRecorder(goodCanary, 0), 0)
	s := testSandbox(t, rec)
	if err := s.StartApp(context.Background(), App{Image: builtImage}); !errors.Is(err, ErrSpec) {
		t.Fatalf("StartApp of an image not built here: %v", err)
	}
	app, err := s.Build(context.Background(), dockerfileRepo(plainDockerfile))
	if err != nil || !app.Built() {
		t.Fatalf("Build = %+v, %v", app, err)
	}
	if err := s.StartApp(context.Background(), app); err != nil {
		t.Fatalf("StartApp: %v", err)
	}
	runs := rec.to("run")
	if len(runs) != 2 || !slices.Contains(runs[0], CanaryImage) {
		t.Fatalf("runs %q: want the canary, then the app", runs)
	}
	appRun := runs[1]
	for _, want := range []string{"--detach", "--network=creep-" + testRunID, "--network-alias=app", "--workdir=/", builtImage} {
		if !slices.Contains(appRun, want) {
			t.Errorf("app run lacks %s: %q", want, appRun)
		}
	}
	if p := hardeningProblems(appRun); len(p) > 0 {
		t.Errorf("app run %q: %v", appRun, p)
	}
	if err := s.StartApp(context.Background(), app); !errors.Is(err, ErrSpec) {
		t.Errorf("second StartApp: %v", err)
	}

	leak := withBuilds(networkRecorder("control-dns=yes\ncontrol-tcp=yes\ndns=yes\ndns-direct=no\ntcp-1.1.1.1=no\ntcp-8.8.8.8=no\n", 0), 0)
	s = testSandbox(t, leak)
	if app, err = s.Build(context.Background(), dockerfileRepo(plainDockerfile)); err != nil || !app.Built() {
		t.Fatalf("Build = %+v, %v", app, err)
	}
	if err := s.StartApp(context.Background(), app); !errors.Is(err, ErrNetworkLeak) {
		t.Errorf("StartApp after a leaking canary: %v", err)
	}
	for _, argv := range leak.to("run") {
		if slices.Contains(argv, builtImage) {
			t.Errorf("the app started after the canary leaked: %q", argv)
		}
	}
}

// TestCloseAndCleanRemoveImages: Close removes the run's built images by
// label and ID after its containers; Clean removes every creep image; a
// listing that holds anything but IDs removes nothing.
func TestCloseAndCleanRemoveImages(t *testing.T) {
	list := func(out string) *recorder {
		return &recorder{reply: func(_ context.Context, args []string) (cliResult, error) {
			if subcommand(args) == "image" && slices.Contains(args, "ls") {
				return cliResult{stdout: []byte(out)}, nil
			}
			return cliResult{}, nil
		}}
	}
	rec := list("sha256:" + fakeID + "\nsha256:" + fakeID + "\n")
	s := testSandbox(t, rec)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	rms := slices.DeleteFunc(rec.to("image"), func(c []string) bool { return !slices.Contains(c, "rm") })
	if len(rms) != 1 || !slices.Equal(rms[0][len(rms[0])-2:], []string{"rm", fakeID}) {
		t.Errorf("image rm calls %q", rms)
	}
	if ps := slices.IndexFunc(rec.calls, func(c []string) bool { return subcommand(c) == "ps" }); ps != 0 {
		t.Errorf("containers not removed first: %q", rec.calls)
	}
	if !slices.Contains(rec.to("image")[0], "label="+LabelRun+"="+testRunID) {
		t.Errorf("Close lists images beyond its run: %q", rec.to("image")[0])
	}
	if !slices.Contains(rec.to("image")[0], "--all") {
		t.Errorf("Close lists tagged images only: %q", rec.to("image")[0])
	}

	// An engine whose listing leaves the built image out: Close still
	// removes it by the ID Build recorded, once, and a second Close asks
	// for nothing more.
	unlisted := withBuilds(list(""), 0)
	s = testSandbox(t, unlisted)
	if app, err := s.Build(context.Background(), dockerfileRepo(plainDockerfile)); err != nil || !app.Built() {
		t.Fatalf("Build = %+v, %v", app, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	rms = slices.DeleteFunc(unlisted.to("image"), func(c []string) bool { return !slices.Contains(c, "rm") })
	if len(rms) != 1 || !slices.Equal(rms[0][len(rms[0])-2:], []string{"rm", fakeID}) {
		t.Errorf("unlisted image rm calls %q", rms)
	}

	bad := list("--force\n")
	s = testSandbox(t, bad)
	if err := s.Close(); err == nil {
		t.Error("Close accepted a listing that is not IDs")
	}
	for _, c := range bad.to("image") {
		if slices.Contains(c, "rm") {
			t.Errorf("removed from a bad listing: %q", c)
		}
	}
}

// TestBuildThroughRealExec drives Build through the real exec path with
// the fake docker, while the operator's DOCKER_CONFIG holds proxies with a
// password: the build reads an empty config (the fake exits 42 otherwise,
// since docker turns config.json proxies into build arguments), and the
// broken path, the operator's config passed to build, is caught.
func TestBuildThroughRealExec(t *testing.T) {
	bin := installFake(t, "docker")
	st := usableDocker()
	st.Path, st.env = bin, []string{"DOCKER_CONFIG=" + proxiedDockerConfig(t)}
	s, err := Open(st, testRunID, Mirror{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	app, err := s.Build(context.Background(), dockerfileRepo(plainDockerfile))
	if err != nil || !app.Built() || app.Image != builtImage {
		t.Fatalf("Build = %+v, %v (build_failed exit_42: the operator's docker config reached the build)", app, err)
	}
	for _, argv := range callsTo(fakeCalls(t, bin), "build") {
		if p := buildProblems(argv, Docker, s.work); len(p) > 0 {
			t.Errorf("build %q: %v", argv, p)
		}
	}
	broken := newExecRunner(bin, st.env)
	argv := buildArgs(st, testRunID, s.work, filepath.Join(s.work, "Dockerfile"), "", filepath.Join(s.work, "iid-x"), Mirror{})
	if res, err := broken(context.Background(), argv, 1024); err != nil || res.exit != 42 {
		t.Errorf("build with the operator's config was not caught: exit %d, %v", res.exit, err)
	}
}

// TestEveryTestAppBuilds runs Build over every app in the test-app
// directory with a recorded runtime, so nothing is executed. Each
// variant's Dockerfile passes the check and reads only the pinned BusyBox
// (CanaryImage, which the real-runtime job pulls), and each build gets
// the offline command line; the test-app guard keeps those bytes. This is
// #23's "works for every app in testdata/apps" without a runtime;
// TestRealTestAppsBuild is the same on a real engine.
func TestEveryTestAppBuilds(t *testing.T) {
	variants := testAppVariants(t)
	for _, dir := range variants {
		repo := dirRepo(t, dir)
		plan, why := planBuild(repo)
		if why != nil || plan.dockerfile != "Dockerfile" || !slices.Equal(plan.images, []string{CanaryImage}) {
			t.Errorf("%s: plan %+v, refused %+v", dir, plan, why)
		}
		rec := withBuilds(&recorder{}, 0)
		s := testSandbox(t, rec)
		app, err := s.Build(context.Background(), repo)
		if err != nil || !app.Built() {
			t.Errorf("%s: Build = %+v, %v", dir, app, err)
		}
		builds := rec.to("build")
		if len(builds) != 1 {
			t.Fatalf("%s: %d builds", dir, len(builds))
		}
		if p := buildProblems(builds[0], Docker, s.work); len(p) > 0 {
			t.Errorf("%s: build %q: %v", dir, builds[0], p)
		}
	}
	if len(variants) < 6 {
		t.Fatalf("found %d app variants", len(variants))
	}
}

// liveApp is the test app that serves for real (#364): its Dockerfile
// installs Flask offline from its committed wheels, so it is planned and
// built by TestLiveTestAppPlans and the live job, not with the BusyBox
// apps.
const liveApp = "flaskpg"

// liveBase is the pinned Python image the live app's Dockerfile reads.
const liveBase = "docker.io/library/python@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90"

// testAppVariants lists every testdata/apps/<app>/<variant> directory
// but the live app's.
func testAppVariants(t *testing.T) []string {
	t.Helper()
	all, err := filepath.Glob(filepath.Join("..", "..", "testdata", "apps", "*", "*"))
	if err != nil {
		t.Fatal(err)
	}
	return slices.DeleteFunc(all, func(dir string) bool {
		info, err := os.Stat(dir)
		return err != nil || !info.IsDir() || filepath.Base(filepath.Dir(dir)) == liveApp
	})
}

// TestLiveTestAppPlans: both variants of the live app plan the same
// offline build, from its root Dockerfile through its compose file, read
// only the pinned Python image, keep the compose file's migrate step, and
// build with the offline command line.
func TestLiveTestAppPlans(t *testing.T) {
	for _, variant := range []string{"vulnerable", "safe"} {
		repo := dirRepo(t, filepath.Join("..", "..", "testdata", "apps", liveApp, variant))
		plan, why := planBuild(repo)
		if why != nil || plan.dockerfile != "Dockerfile" || !slices.Equal(plan.images, []string{liveBase}) ||
			!slices.Equal(plan.migrate, []string{"python", "migrate.py"}) {
			t.Fatalf("%s: plan %s %q migrate %q, refused %+v", variant, plan.dockerfile, plan.images, plan.migrate, why)
		}
		rec := withBuilds(&recorder{}, 0)
		s := testSandbox(t, rec)
		app, err := s.Build(context.Background(), repo)
		if err != nil || !app.Built() || !slices.Equal(app.MigrateCommand(), plan.migrate) {
			t.Fatalf("%s: Build = %+v, %v", variant, app, err)
		}
		for _, argv := range rec.to("build") {
			if p := buildProblems(argv, Docker, s.work); len(p) > 0 {
				t.Errorf("%s: build %q: %v", variant, argv, p)
			}
		}
	}
}

func dirRepo(t *testing.T, dir string) Repo {
	t.Helper()
	fsys := os.DirFS(dir)
	var paths []string
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() {
			paths = append(paths, p)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return Repo{Paths: paths, Read: func(p string) ([]byte, error) { return fs.ReadFile(fsys, p) }}
}
