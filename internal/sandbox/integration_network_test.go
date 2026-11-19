package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

// The network integration tests need the pinned canary and database
// images. creep never pulls; the test pulls them by digest, as an operator
// would, so they need a registry the first time (CI has one).

// pullPinned makes the pinned images present on st.
func pullPinned(t *testing.T, st Status) {
	t.Helper()
	for _, ref := range []string{CanaryImage, DatabaseImage} {
		if _, code := cliCode(t, st, "image", "inspect", "--format", "{{.Id}}", ref); code == 0 {
			continue
		}
		cli(t, st, "pull", ref)
	}
}

// cliCode runs the runtime CLI for the test and returns stdout and the
// exit code instead of failing on a non-zero one.
func cliCode(t *testing.T, st Status, args ...string) (string, int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	res, err := newExecRunner(st.Path, st.env)(ctx, append(globalArgs(st), args...), infoLimit)
	if err != nil {
		t.Fatalf("%s %q: %v", st.Runtime, args, err)
	}
	return strings.TrimSpace(string(res.stdout)), res.exit
}

func openReal(t *testing.T, st Status) *Sandbox {
	t.Helper()
	s, err := Open(st, "itest-"+strings.ToLower(uniqueSuffix()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

const synthRow = "synthetic-row-from-migration"

// TestRealNetworkIsolated runs a real run network end to end: the canary
// passes, the database is seeded from a migration and nothing else, a PoC
// that tries the internet fails while it reaches the database, no port is
// published, nothing on the host's network reaches the database, and Close
// removes the network.
func TestRealNetworkIsolated(t *testing.T) {
	eachRuntime(t, func(t *testing.T, st Status) {
		pullPinned(t, st)
		probe := probeImage(t, st)
		t.Setenv("DATABASE_URL", "postgres://real:"+hostMarker+"@prod.example/app")
		s := openReal(t, st)
		db, err := s.StartDatabase(context.Background(), []Migration{{Path: "migrations/1_init.sql",
			SQL: []byte("CREATE TABLE items (id serial PRIMARY KEY, name text NOT NULL); INSERT INTO items (name) VALUES ('" + synthRow + "');")}})
		if err != nil {
			t.Fatal(err)
		}
		res, err := s.RunBatch(context.Background(), []Spec{{Image: probe, Cmd: []string{"/probe", "internet"}, Timeout: 2 * time.Minute}})
		if err != nil || res[0].ExitCode != 0 || string(res[0].Output) != "ok" {
			t.Fatalf("PoC trying the internet: %v %+v: %s", err, res, firstOutput(res))
		}
		checkDatabaseHoldsOnlySeed(t, s, db)
		dbID := waitForContainer(t, st, LabelRun+"="+s.runID)
		checkNoHostReach(t, st, s, dbID, probe)
		if err := s.Close(); err != nil {
			left, _ := cliCode(t, st, "ps", "--all", "--filter", "label="+LabelRun+"="+s.runID, "--format", "{{.ID}} {{.Image}} {{.Status}}")
			t.Fatalf("Close: %v; left: %s", err, left)
		}
		if left, _ := cliCode(t, st, "network", "ls", "--quiet", "--filter", "label="+LabelRun+"="+s.runID); left != "" {
			t.Errorf("Close left network %s", left)
		}
	})
}

func firstOutput(res []Result) string {
	if len(res) == 0 {
		return ""
	}
	return string(res[0].Output)
}

// checkDatabaseHoldsOnlySeed dumps the database from a client on the
// network: the migration's table and row are there, nothing else is, and
// no host data is.
func checkDatabaseHoldsOnlySeed(t *testing.T, s *Sandbox, db Database) {
	t.Helper()
	if err := s.clearNetwork(context.Background()); err != nil {
		t.Fatal(err)
	}
	res, err := s.start(context.Background(), Spec{
		Image: DatabaseImage, Cmd: []string{"pg_dump", "-h", db.Host, "-U", db.User, "-d", db.Name, "--no-owner"},
		Env: map[string]string{"PGPASSWORD": db.Password}, Timeout: time.Minute, networked: true, tmpfs: []string{pgData},
	})
	dump := string(res.Output)
	if err != nil || res.ExitCode != 0 {
		t.Fatalf("pg_dump: %v exit %d: %s", err, res.ExitCode, dump)
	}
	switch {
	case !strings.Contains(dump, "CREATE TABLE public.items") || !strings.Contains(dump, synthRow):
		t.Errorf("the migration is missing from the database:\n%s", dump)
	case strings.Count(dump, "CREATE TABLE") != 1:
		t.Errorf("tables beyond the migration's:\n%s", dump)
	case strings.Contains(dump, hostMarker):
		t.Errorf("host data in the database:\n%s", dump)
	}
}

// mountPoint is the part of `inspect .Mounts` the test checks.
type mountPoint struct {
	Type, Source, Destination string
	RW                        bool
}

// checkNoHostReach: the runtime publishes no port of the database, its
// only mount is the read-only seed in the work directory (the data is a
// tmpfs, the image VOLUME got no host volume), and a container on the
// host's own network cannot connect to it.
func checkNoHostReach(t *testing.T, st Status, s *Sandbox, id, probe string) {
	t.Helper()
	// An image's EXPOSE shows up as a port with no host binding (null);
	// any binding at all is a published port.
	for _, field := range []string{".NetworkSettings.Ports", ".HostConfig.PortBindings"} {
		var bindings map[string][]json.RawMessage
		out := cli(t, st, "inspect", "--format", "{{json "+field+"}}", id)
		if err := json.Unmarshal([]byte(out), &bindings); err != nil {
			t.Fatalf("%s: %v: %s", field, err, out)
		}
		for port, b := range bindings {
			if len(b) > 0 {
				t.Errorf("%s publishes %s: %s", field, port, out)
			}
		}
	}
	if all := cli(t, st, "inspect", "--format", "{{.HostConfig.PublishAllPorts}}", id); all != "false" {
		t.Errorf("PublishAllPorts %s", all)
	}
	var mounts []mountPoint
	if err := json.Unmarshal([]byte(cli(t, st, "inspect", "--format", "{{json .Mounts}}", id)), &mounts); err != nil {
		t.Fatal(err)
	}
	// Podman may list the tmpfs mounts too; they hold no host data.
	mounts = slices.DeleteFunc(mounts, func(m mountPoint) bool {
		return m.Type == "tmpfs" && slices.Contains([]string{pgData, pgSocket, "/tmp"}, m.Destination)
	})
	if len(mounts) != 1 || mounts[0].Type != "bind" || mounts[0].RW || mounts[0].Destination != seedTarget ||
		!strings.HasPrefix(mounts[0].Source, s.workReal) {
		t.Errorf("database mounts %+v, want only the seed from %s", mounts, s.workReal)
	}
	ip := cli(t, st, "inspect", "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", id)
	if ip == "" {
		t.Fatal("database has no address on the run network")
	}
	// A test-only container on the host's network stands for the host: on
	// Docker Desktop that is the VM the daemon runs in.
	if got, _ := cliCode(t, st, "run", "--rm", "--pull=never", "--network=host", probe, "/probe", "dial", ip+":5432"); got != "unreachable" {
		t.Errorf("the host reaches the database at %s: %s", ip, got)
	}
}

// TestRealCanaryCatchesLeak proves the canary can fail: on a network that
// is not internal, a machine with internet access gets ErrNetworkLeak,
// the PoC never starts and the run stays aborted.
func TestRealCanaryCatchesLeak(t *testing.T) {
	eachRuntime(t, func(t *testing.T, st Status) {
		pullPinned(t, st)
		probe := probeImage(t, st)
		s := openReal(t, st)
		s.netArgs = func(st Status, name, runID string) []string {
			return slices.DeleteFunc(networkArgs(st, name, runID), func(a string) bool {
				return a == "--internal" || strings.HasPrefix(a, "--opt=")
			})
		}
		_, err := s.RunBatch(context.Background(), []Spec{{Image: probe, Cmd: []string{"/probe", "sleep"}}})
		switch {
		case err == nil && os.Getenv(requireEnv) == "":
			t.Skip("this machine has no internet access, so a leaky network looks like an internal one")
		case !errors.Is(err, ErrNetworkLeak):
			t.Fatalf("leaky network: %v, want ErrNetworkLeak", err)
		}
		if left := cli(t, st, "ps", "--all", "--quiet", "--filter", "label="+LabelRun+"="+s.runID); left != "" {
			t.Errorf("a container of the aborted run is left: %s", left)
		}
		if _, err := s.RunBatch(context.Background(), []Spec{{Image: probe}}); !errors.Is(err, ErrNetworkLeak) {
			t.Errorf("run not aborted: %v", err)
		}
	})
}

// TestRealHostReachWithoutInhibit proves the host check can fail: on
// Docker's rootful daemon or Docker Desktop, an internal network whose
// bridge keeps a host address lets the host reach the database.
func TestRealHostReachWithoutInhibit(t *testing.T) {
	eachRuntime(t, func(t *testing.T, st Status) {
		if st.Runtime != Docker || st.Rootless {
			t.Skip("only Docker's own network namespace has the bridge address")
		}
		pullPinned(t, st)
		probe := probeImage(t, st)
		s := openReal(t, st)
		s.netArgs = func(st Status, name, runID string) []string {
			return slices.DeleteFunc(networkArgs(st, name, runID), func(a string) bool { return strings.HasPrefix(a, "--opt=") })
		}
		if _, err := s.StartDatabase(context.Background(), nil); err != nil {
			t.Fatal(err)
		}
		id := waitForContainer(t, st, LabelRun+"="+s.runID)
		ip := cli(t, st, "inspect", "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", id)
		// Docker Desktop and a rootful Linux daemon both reach it; an engine
		// whose own rules already cut the host off cannot show the check
		// failing, so the proof skips there instead.
		if got, _ := cliCode(t, st, "run", "--rm", "--pull=never", "--network=host", probe, "/probe", "dial", ip+":5432"); got != "reachable" {
			t.Skipf("this engine keeps the host off %s even without inhibit_ipv4 (%s)", ip, got)
		}
	})
}

// TestRealCleanRemovesNetworks: creep clean removes the network a killed
// run left, by creep's label.
func TestRealCleanRemovesNetworks(t *testing.T) {
	eachRuntime(t, func(t *testing.T, st Status) {
		s := openReal(t, st)
		if err := s.ensureNetwork(context.Background()); err != nil {
			t.Fatal(err)
		}
		removed, err := Clean(context.Background(), st)
		if err != nil || removed.Networks < 1 {
			t.Fatalf("Clean: %+v, %v", removed, err)
		}
		if left, _ := cliCode(t, st, "network", "ls", "--quiet", "--filter", "label="+LabelManaged+"=true"); left != "" {
			t.Errorf("creep clean left network %s", left)
		}
	})
}
