package sandbox

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func dockerServerWith(engine, runc string) string {
	return `{"Components":[{"Name":"Engine","Version":"` + engine + `"},{"Name":"runc","Version":"` + runc + `"}]}`
}

func podmanWith(buildah, runtime, version string) string {
	return strings.NewReplacer(`"buildahVersion":"1.35.3"`, `"buildahVersion":"`+buildah+`"`,
		`"name":"crun"`, `"name":"`+runtime+`"`,
		`crun version 1.14.4`, version).Replace(podmanRootless)
}

// TestRuntimeMinimums is the protection test for the engine minimums
// (final v0.2 release pentest): a runtime below them, or one whose
// versions creep cannot read, is not usable, so nothing is built or run
// on it and creep reproduce exits 3.
func TestRuntimeMinimums(t *testing.T) {
	ctx := `"unix:///run/user/1000/docker.sock"`
	tests := map[string]struct {
		docker fakeRuntime
		podman string
		want   [2]Reason
	}{
		"both patched":           {fakeRuntime{context: ctx, info: dockerRootless}, podmanRootless, [2]Reason{ReasonOK, ReasonOK}},
		"current releases":       {fakeRuntime{context: ctx, info: dockerRootless, version: dockerServerWith("29.7.2", "1.3.6")}, podmanWith("1.41.4", "runc", "runc version 1.3.0"), [2]Reason{ReasonOK, ReasonOK}},
		"distribution suffixes":  {fakeRuntime{context: ctx, info: dockerRootless, version: dockerServerWith("26.1.3+dfsg1", "1.1.12-0ubuntu2~22.04.1")}, podmanWith("1.35.3", "crun", "crun version 1.15"), [2]Reason{ReasonOK, ReasonOK}},
		"engine before BuildKit": {fakeRuntime{context: ctx, info: dockerRootless, version: dockerServerWith("25.0.1", "1.1.12")}, podmanWith("1.35.2", "crun", "crun version 1.14.4"), [2]Reason{ReasonOldRuntime, ReasonOldRuntime}},
		"old engine line":        {fakeRuntime{context: ctx, info: dockerRootless, version: dockerServerWith("24.0.9", "1.1.12")}, podmanWith("1.33.7", "crun", "crun version 1.14.4"), [2]Reason{ReasonOldRuntime, ReasonOldRuntime}},
		"runc leaks fds":         {fakeRuntime{context: ctx, info: dockerRootless, version: dockerServerWith("25.0.2", "1.1.11")}, podmanWith("1.35.3", "runc", `runc version 1.1.11\ncommit: v1.1.11`), [2]Reason{ReasonOldRuntime, ReasonOldRuntime}},
		"old crun":               {fakeRuntime{context: ctx, info: dockerRootless}, podmanWith("1.35.3", "crun", "crun version 1.4.3"), [2]Reason{ReasonOK, ReasonOldRuntime}},
		"no runc component":      {fakeRuntime{context: ctx, info: dockerRootless, version: `{"Components":[{"Name":"Engine","Version":"29.7.2"}]}`}, podmanWith("", "crun", "crun version 1.14.4"), [2]Reason{ReasonUnknownVersion, ReasonUnknownVersion}},
		"two runc components":    {fakeRuntime{context: ctx, info: dockerRootless, version: `{"Components":[{"Name":"Engine","Version":"29.7.2"},{"Name":"runc","Version":"1.0.0"},{"Name":"runc","Version":"1.3.6"}]}`}, podmanWith("1.35.3", "youki", "youki version 0.3.3"), [2]Reason{ReasonUnknownVersion, ReasonUnknownVersion}},
		"version fails":          {fakeRuntime{context: ctx, info: dockerRootless, version: "-"}, podmanWith("1.35.3", "runc", "runc 1.1.12"), [2]Reason{ReasonUnknownVersion, ReasonUnknownVersion}},
		"version not json":       {fakeRuntime{context: ctx, info: dockerRootless, version: "25.0.2"}, podmanWith("1.35", "runc", ""), [2]Reason{ReasonUnknownVersion, ReasonOldRuntime}},
		"unparsable versions":    {fakeRuntime{context: ctx, info: dockerRootless, version: dockerServerWith("dev", "1.1.12")}, podmanWith("v1.35.x", "runc", "runc version 1.1.12"), [2]Reason{ReasonUnknownVersion, ReasonUnknownVersion}},
		"huge version part":      {fakeRuntime{context: ctx, info: dockerRootless, version: dockerServerWith("99999999999.0.0", "1.1.12")}, podmanWith("1.35.3", "runc", "runc version 1.99999999999.0"), [2]Reason{ReasonUnknownVersion, ReasonUnknownVersion}},
		"another default":        {fakeRuntime{context: ctx, info: strings.Replace(dockerRootless, `"DefaultRuntime":"runc"`, `"DefaultRuntime":"crun"`, 1)}, podmanRootless, [2]Reason{ReasonUnknownVersion, ReasonOK}},
		"no default runtime":     {fakeRuntime{context: ctx, info: strings.Replace(dockerRootless, `,"DefaultRuntime":"runc"`, ``, 1)}, podmanRootless, [2]Reason{ReasonUnknownVersion, ReasonOK}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			rt := map[string]fakeRuntime{"docker": tt.docker, "podman": {info: tt.podman}}
			bins := map[string]string{"docker": fakeBin(t, "docker"), "podman": fakeBin(t, "podman")}
			p := prober{
				look: func(name string) (string, error) { return bins[name], nil },
				start: func(bin string, _ []string) runFunc {
					return rt[strings.TrimSuffix(filepath.Base(bin), ".exe")].runner(&recorder{})
				},
				os: "linux",
			}
			rep := detect(context.Background(), Env{Repo: t.TempDir(), Getenv: func(string) string { return "" }}, p)
			got := [2]Reason{rep.Checked[0].Reason, rep.Checked[1].Reason}
			if got != tt.want {
				t.Errorf("reasons = %v, want %v", got, tt.want)
			}
			for _, st := range rep.Checked {
				if !st.Usable() && st.Isolation != IsolationNone {
					t.Errorf("%s unusable with isolation %s", st.Runtime, st.Isolation)
				}
			}
		})
	}
}

// TestDockerVersionThroughPinnedHost checks the version query goes to the
// endpoint detection pinned, in a fixed format.
func TestDockerVersionThroughPinnedHost(t *testing.T) {
	rec := &recorder{}
	run := fakeRuntime{context: `"unix:///run/user/1000/docker.sock"`, info: dockerRootless}.runner(rec)
	st := probeDocker(context.Background(), run, func(string) string { return "" }, Status{Runtime: Docker})
	if !st.Usable() {
		t.Fatalf("reason %s", st.Reason)
	}
	calls := rec.to("version")
	want := []string{"--host=unix:///run/user/1000/docker.sock", "version", "--format", "{{json .Server}}"}
	if len(calls) != 1 || strings.Join(calls[0], " ") != strings.Join(want, " ") {
		t.Errorf("version calls %q, want %q", calls, want)
	}
}

func TestParseVersion(t *testing.T) {
	tests := map[string]struct {
		in   string
		want engineVersion
		ok   bool
	}{
		"plain":       {"1.1.12", engineVersion{1, 1, 12}, true},
		"v prefix":    {"v2.2.5", engineVersion{2, 2, 5}, true},
		"two parts":   {"1.15", engineVersion{1, 15, 0}, true},
		"suffix":      {"1.1.12-0ubuntu2~22.04.1", engineVersion{1, 1, 12}, true},
		"newline":     {"1.3.6\n", engineVersion{1, 3, 6}, true},
		"build":       {"26.1.3+dfsg1", engineVersion{26, 1, 3}, true},
		"one part":    {"25", engineVersion{}, false},
		"four parts":  {"1.2.3.4", engineVersion{}, false},
		"empty part":  {"1..2", engineVersion{}, false},
		"sign":        {"1.+1.2", engineVersion{}, false},
		"letters":     {"1.a.2", engineVersion{}, false},
		"empty":       {"", engineVersion{}, false},
		"too long":    {"1.1234567.0", engineVersion{}, false},
		"just suffix": {"-rc1", engineVersion{}, false},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, ok := parseVersion(tt.in)
			if got != tt.want || ok != tt.ok {
				t.Errorf("parseVersion(%q) = %v %v, want %v %v", tt.in, got, ok, tt.want, tt.ok)
			}
		})
	}
}
