package sandbox

import (
	"context"
	"testing"
)

// TestRealMirrorBuild runs ADR 0029's build mirror on a real engine, with
// the test as the operator: it creates an internal network (with no
// mirror on it) and points the sandbox at it. Docker's BuildKit cannot run
// a build there, so the build is refused before it starts. On rootless
// Podman the canary passes, a RUN step that tries a host outside the
// network fails the build, and a network with a route out is refused.
func TestRealMirrorBuild(t *testing.T) {
	eachRuntime(t, func(t *testing.T, st Status) {
		pullPinned(t, st)
		internal := operatorNetwork(t, st, true)
		s := openReal(t, st)
		s.UseMirror(Mirror{Bridge: internal, Proxy: "http://mirror.invalid:3128"})
		reach := (&memRepo{files: map[string]string{
			"Dockerfile": "FROM " + CanaryImage + "\nRUN wget -q -T 5 -O /dev/null http://1.1.1.1/ || nc -w 3 8.8.8.8 53 </dev/null\n",
		}}).repo()
		got, err := s.Build(context.Background(), reach)
		if err != nil {
			t.Fatal(err)
		}
		switch {
		case st.Runtime == Docker && (got.Unavailable != BuildMirrorRefused || got.Detail != mirrorBuilder):
			t.Errorf("Docker with a mirror: %+v, want mirror_refused/builder", got)
		case st.Runtime == Podman && !st.Rootless && got.Detail != mirrorRootful:
			t.Errorf("rootful Podman with a mirror: %+v, want mirror_refused/rootful", got)
		case st.Runtime == Podman && st.Rootless && got.Unavailable != BuildFailed:
			t.Errorf("a build that reaches past the mirror: %+v, want build_failed", got)
		}
		if st.Runtime != Podman || !st.Rootless {
			return
		}
		s.UseMirror(Mirror{Bridge: operatorNetwork(t, st, false)})
		if got, err := s.Build(context.Background(), reach); err != nil || got.Detail != mirrorNotInternal {
			t.Errorf("a routed network: %+v, %v; want mirror_refused/not_internal", got, err)
		}
	})
}

// operatorNetwork creates a bridge network as an operator would, internal
// or routed, and removes it when the test ends.
func operatorNetwork(t *testing.T, st Status, internal bool) string {
	t.Helper()
	name := "creep-itest-mirror-" + uniqueSuffix()
	args := []string{"network", "create", "--driver=bridge", "--ipv6=false"}
	if internal {
		args = append(args, "--internal")
	}
	cli(t, st, append(args, name)...)
	t.Cleanup(func() { _, _ = cliCode(t, st, "network", "rm", name) })
	return name
}
