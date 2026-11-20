package sandbox

import (
	"context"
	"strings"
	"testing"
)

// TestRealBuildIsOffline builds on a real engine, from the pinned BusyBox
// as the only base image: a build gets the repository's files but not its
// .env, a RUN step that tries to reach a public address fails the build
// (verification unavailable, not an error), a missing base image is never
// pulled, and Close removes the built image.
func TestRealBuildIsOffline(t *testing.T) {
	eachRuntime(t, func(t *testing.T, st Status) {
		pullPinned(t, st)
		s := openReal(t, st)
		repo := (&memRepo{files: map[string]string{
			"Dockerfile": "FROM " + CanaryImage + "\nCOPY . /app\nRUN test -f /app/hello.txt && test ! -e /app/.env\n",
			"hello.txt":  "hello from the repository\n",
			".env":       "SECRET=must-not-be-copied\n",
		}}).repo()
		app, err := s.Build(context.Background(), repo)
		if err != nil || !app.Built() {
			t.Fatalf("Build = %+v, %v", app, err)
		}
		res, err := s.Run(context.Background(), Spec{Image: app.Image, Cmd: []string{"cat", "/app/hello.txt"}})
		if err != nil || res.ExitCode != 0 || !strings.Contains(string(res.Output), "hello from the repository") {
			t.Fatalf("Run of the built image = %+v, %v", res, err)
		}

		reach := (&memRepo{files: map[string]string{
			"Dockerfile": "FROM " + CanaryImage + "\nRUN wget -q -T 5 -O /dev/null http://1.1.1.1/ || nc -w 3 8.8.8.8 53 </dev/null\n",
		}}).repo()
		if got, err := s.Build(context.Background(), reach); err != nil || got.Unavailable != BuildFailed {
			t.Errorf("a build that reaches out: %+v, %v; want build_failed", got, err)
		}

		missing := "docker.io/library/busybox@sha256:" + strings.Repeat("0", 64)
		if got, err := s.Build(context.Background(), (&memRepo{files: map[string]string{"Dockerfile": "FROM " + missing + "\n"}}).repo()); err != nil || got.Unavailable != BuildBaseImageMissing {
			t.Errorf("missing base image: %+v, %v", got, err)
		}
		if _, code := cliCode(t, st, "image", "inspect", missing); code == 0 {
			t.Error("the missing base image was pulled")
		}

		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		if _, code := cliCode(t, st, "image", "inspect", app.Image); code == 0 {
			t.Errorf("Close left the built image %s", app.Image)
		}
	})
}

// TestRealTestAppsBuild builds every test app on a real engine, offline,
// from the pinned BusyBox its shared Dockerfile names: each image holds
// the app's files, and Close removes it. The image does not serve the app:
// an offline build cannot install Flask, FastAPI or Express (#277).
func TestRealTestAppsBuild(t *testing.T) {
	eachRuntime(t, func(t *testing.T, st Status) {
		pullPinned(t, st)
		s := openReal(t, st)
		var images []string
		for _, dir := range testAppVariants(t) {
			app, err := s.Build(context.Background(), dirRepo(t, dir))
			if err != nil || !app.Built() {
				t.Errorf("%s: Build = %+v, %v", dir, app, err)
				continue
			}
			images = append(images, app.Image)
			res, err := s.Run(context.Background(), Spec{Image: app.Image, Cmd: []string{"test", "-f", "/app/Dockerfile"}})
			if err != nil || res.ExitCode != 0 {
				t.Errorf("%s: the built image lacks the app's files: %+v, %v", dir, res, err)
			}
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		for _, image := range images {
			if _, code := cliCode(t, st, "image", "inspect", image); code == 0 {
				t.Errorf("Close left the built image %s", image)
			}
		}
	})
}
