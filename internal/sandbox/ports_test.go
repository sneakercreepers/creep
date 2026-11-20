package sandbox

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
)

// publishProblems finds, in any command line, an option that publishes a
// port or puts a container on the host's network.
func publishProblems(argv []string) []string {
	var problems []string
	for i, a := range argv {
		next := ""
		if i+1 < len(argv) {
			next = argv[i+1]
		}
		switch {
		case a == "-p", a == "-P", strings.HasPrefix(a, "-p="), strings.HasPrefix(a, "--publish"), strings.HasPrefix(a, "--expose"):
			problems = append(problems, "publishes: "+a)
		case a == "--network=host", a == "--net=host", (a == "--network" || a == "--net") && next == "host":
			problems = append(problems, "host network: "+a)
		}
	}
	return problems
}

// publishWeakened inserts, after `run`, each option that would make a port
// reachable from the host or leave the internal network.
func publishWeakened(good []string) map[string][]string {
	extra := map[string][]string{
		"-p":                {"-p", "8080:80"},
		"-p=":               {"-p=127.0.0.1:5432:5432"},
		"--publish":         {"--publish=8080:80"},
		"--publish two":     {"--publish", "80"},
		"--publish-all":     {"--publish-all"},
		"-P":                {"-P"},
		"--expose":          {"--expose=80"},
		"host network":      {"--network=host"},
		"--net host":        {"--net", "host"},
		"default bridge":    {"--network=bridge"},
		"another container": {"--network=container:postgres"},
		"another network":   {"--network=creep-other-run"},
		"second network":    {"--network=none"},
		"public DNS":        {"--dns=8.8.8.8"},
		"extra host":        {"--add-host=db:203.0.113.7"},
	}
	out := map[string][]string{}
	for name, opts := range extra {
		i := slices.Index(good, "run") + 1
		out["publish "+name] = slices.Insert(slices.Clone(good), i, opts...)
	}
	return out
}

// TestNoPortPublished is the protection test for host reachability: no
// command line of a whole run (network, canary, database, PoCs, the app's
// build and container, cleanup) publishes a port or uses the host network; the network is internal,
// Docker's bridge gets no host address, and rootful Podman, whose bridge
// keeps one, gets no network at all. Each weakened line is caught.
func TestNoPortPublished(t *testing.T) {
	podman := usableDocker()
	podman.Runtime, podman.Host = Podman, ""
	for _, st := range []Status{usableDocker(), podman} {
		t.Run(string(st.Runtime), func(t *testing.T) {
			rec := withBuilds(networkRecorder(goodCanary, 0), 0)
			s, err := newSandbox(st, testRunID, rec.run)
			if err != nil {
				t.Fatal(err)
			}
			runWholeFlow(t, s)
			for _, argv := range rec.calls {
				if p := publishProblems(argv); len(p) > 0 {
					t.Errorf("%q: %v", argv, p)
				}
			}
			checkNetworkCreate(t, st, rec)
		})
	}
	good, err := testSandbox(t, &recorder{}).runArgs("creep-"+testRunID+"-1", Spec{Image: testImage})
	if err != nil {
		t.Fatal(err)
	}
	for name, argv := range publishWeakened(good) {
		if len(publishProblems(argv)) == 0 && len(hardeningProblems(argv)) == 0 {
			t.Errorf("%s: weakened run %q passed both checks", name, argv)
		}
	}
	rootful := podman
	rootful.Rootless, rootful.Isolation = false, IsolationRootful
	rec := networkRecorder(goodCanary, 0)
	s, err := newSandbox(rootful, testRunID, rec.run)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.RunBatch(context.Background(), []Spec{{Image: testImage}}); !errors.Is(err, ErrHostReachable) {
		t.Errorf("rootful podman: %v", err)
	}
	if len(rec.to("run")) != 0 || len(rec.to("network")) != 0 {
		t.Errorf("rootful podman created something: %q", rec.calls)
	}
}

func runWholeFlow(t *testing.T, s *Sandbox) {
	t.Helper()
	if _, err := s.StartDatabase(context.Background(), []Migration{{Path: "migrations/1.sql", SQL: []byte("SELECT 1;")}}); err != nil {
		t.Fatalf("StartDatabase: %v", err)
	}
	if _, err := s.RunBatch(context.Background(), []Spec{{Image: testImage, Env: map[string]string{"PORT": "8080"}}}); err != nil {
		t.Fatalf("RunBatch: %v", err)
	}
	app, err := s.Build(context.Background(), dockerfileRepo("FROM alpine:3\nEXPOSE 8080\n"))
	if err != nil || !app.Built() {
		t.Fatalf("Build = %+v, %v", app, err)
	}
	if err := s.StartApp(context.Background(), app); err != nil {
		t.Fatalf("StartApp: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}

// checkNetworkCreate pins the network command line: internal, IPv4 only,
// Docker's bridge without a host address, creep's labels, the run's name.
func checkNetworkCreate(t *testing.T, st Status, rec *recorder) {
	t.Helper()
	var creates [][]string
	for _, c := range rec.to("network") {
		if slices.Contains(c, "create") {
			creates = append(creates, c)
		}
	}
	if len(creates) != 1 {
		t.Fatalf("%d network creates", len(creates))
	}
	want := append(globalArgs(st), "network", "create", "--driver=bridge", "--internal", "--ipv6=false")
	if st.Runtime == Docker {
		want = append(want, "--opt=com.docker.network.bridge.inhibit_ipv4=true")
	}
	want = append(want, "--label="+LabelManaged+"=true", "--label="+LabelRun+"="+testRunID, "creep-"+testRunID)
	if !slices.Equal(creates[0], want) {
		t.Errorf("network create %q, want %q", creates[0], want)
	}
}
