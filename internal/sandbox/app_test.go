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
	for _, want := range []string{"--detach", "--network=creep-" + testRunID, "--network-alias=app", builtImage} {
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
	s, err := Open(st, testRunID)
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
	argv := buildArgs(st, testRunID, s.work, filepath.Join(s.work, "Dockerfile"), "", filepath.Join(s.work, "iid-x"))
	if res, err := broken(context.Background(), argv, 1024); err != nil || res.exit != 42 {
		t.Errorf("build with the operator's config was not caught: exit %d, %v", res.exit, err)
	}
}

// TestEveryTestAppGetsAnOutcome runs Build over every app in the test-app
// directory with a recorded runtime: nothing is executed. None ships a
// compose file or Dockerfile (the test-app guard forbids build files), so
// each one is verification unavailable, no_build_file, and never an error.
func TestEveryTestAppGetsAnOutcome(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "apps")
	variants, err := filepath.Glob(filepath.Join(root, "*", "*"))
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, dir := range variants {
		if info, err := os.Stat(dir); err != nil || !info.IsDir() {
			continue
		}
		seen++
		rec := withBuilds(&recorder{}, 0)
		s := testSandbox(t, rec)
		app, err := s.Build(context.Background(), dirRepo(t, dir))
		if err != nil || app.Built() || app.Unavailable != BuildNoFile {
			t.Errorf("%s: Build = %+v, %v", dir, app, err)
		}
		if len(rec.calls) != 0 {
			t.Errorf("%s: calls %q", dir, rec.calls)
		}
	}
	if seen < 6 {
		t.Fatalf("found %d app variants", seen)
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
