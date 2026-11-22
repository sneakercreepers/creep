package sandbox

import (
	"context"
	"errors"
	"path"
	"slices"
	"strings"
	"testing"
)

// engineEscapes are the Dockerfiles of the final v0.2 release pentest:
// escapes only a patched runc, BuildKit or Buildah blocks, and an image
// transport that skips the registry name. Each must be refused.
var engineEscapes = map[string]struct{ file, rule string }{
	// runc < 1.1.12 (CVE-2024-21626): a leaked host directory as the cwd.
	"WORKDIR proc fd":        {"FROM busybox\nWORKDIR /proc/self/fd/8\nRUN cd ../../.. && cat etc/shadow\n", ruleContainerPath},
	"WORKDIR relative proc":  {"FROM busybox\nWORKDIR /\nWORKDIR proc/self/fd/8\n", ruleContainerPath},
	"WORKDIR climbs to proc": {"FROM busybox\nWORKDIR /app/../proc/self/fd/7\n", ruleContainerPath},
	"WORKDIR climbs up":      {"FROM busybox\nWORKDIR ../proc/self/fd/7\n", ruleContainerPath},
	"WORKDIR double slash":   {"FROM busybox\nWORKDIR //proc/self/fd/8\n", ruleContainerPath},
	"WORKDIR dot segments":   {"FROM busybox\nWORKDIR /./proc/./self/fd/8/\n", ruleContainerPath},
	"WORKDIR dev fd":         {"FROM busybox\nWORKDIR /dev/fd/8\n", ruleContainerPath},
	"WORKDIR sys":            {"FROM busybox\nWORKDIR /sys/fs/cgroup\n", ruleContainerPath},
	"WORKDIR proc itself":    {"FROM busybox\nWORKDIR /proc\n", ruleContainerPath},
	"WORKDIR variable":       {"FROM busybox\nENV D=/proc/self/fd/8\nWORKDIR $D\n", ruleContainerPath},
	"WORKDIR braced var":     {"FROM busybox\nARG D=/proc/self/fd/8\nWORKDIR ${D}\n", ruleContainerPath},
	"WORKDIR escaped":        {"FROM busybox\nWORKDIR /pr\\oc/self/fd/8\n", ruleContainerPath},
	"WORKDIR quoted":         {"FROM busybox\nWORKDIR \"/proc/self/fd/8\"\n", ruleContainerPath},
	"WORKDIR split":          {"FROM busybox\nWORKDIR /pr\\\noc/self/fd/8\n", ruleContainerPath},
	"WORKDIR lower case":     {"FROM busybox\nworkdir /proc/self/fd/8\n", ruleContainerPath},
	"WORKDIR two words":      {"FROM busybox\nWORKDIR /app /proc/self/fd/8\n", ruleContainerPath},
	"WORKDIR empty":          {"FROM busybox\nWORKDIR\n", ruleContainerPath},
	// Buildah < 1.35.3 (CVE-2024-1753): a link in another stage's source
	// resolved on the host, mounting its root read-write.
	"mount from stage rw":   {"FROM busybox AS s\nRUN ln -s / /l\nFROM busybox\nRUN --mount=type=bind,from=s,source=l,target=/h,rw cat /h/etc/shadow\n", ruleMountFrom},
	"mount from stage ro":   {"FROM busybox AS s\nRUN ln -s / /l\nFROM busybox\nRUN --mount=type=bind,from=s,source=l,target=/h cat /h/etc/shadow\n", ruleMountFrom},
	"mount from upper case": {"FROM busybox AS s\nFROM busybox\nRUN --mount=FROM=s,src=l,dst=/h true\n", ruleMountFrom},
	"mount from image":      {"FROM busybox\nRUN --mount=type=bind,from=busybox,source=/,target=/h true\n", ruleMountFrom},
	"mount from split":      {"FROM busybox\nRUN --mount=type=bind,fr\\\nom=attacker.example/evil,target=/m true\n", ruleMountFrom},
	"mount from after rw":   {"FROM busybox AS s\nFROM busybox\nRUN --mount=rw,target=/h,from=s true\n", ruleMountFrom},
	"mount from second":     {"FROM busybox AS s\nFROM busybox\nRUN --mount=type=tmpfs,target=/t --mount=from=s,target=/h true\n", ruleMountFrom},
	// BuildKit < 0.12.5 (CVE-2024-23652): a mount target through a link.
	"tmpfs target proc":      {"FROM busybox\nRUN --mount=type=tmpfs,target=/proc/self/fd/8 true\n", ruleContainerPath},
	"bind target dev":        {"FROM busybox\nRUN --mount=type=bind,source=x,target=/dev/shm true\n", ruleContainerPath},
	"dst target sys":         {"FROM busybox\nRUN --mount=type=tmpfs,dst=/sys/kernel true\n", ruleContainerPath},
	"destination climbs":     {"FROM busybox\nRUN --mount=type=tmpfs,destination=../x true\n", ruleContainerPath},
	"target dot dot proc":    {"FROM busybox\nRUN --mount=type=tmpfs,TARGET=/x/../../proc/1 true\n", ruleContainerPath},
	"target relative proc":   {"FROM busybox\nRUN --mount=type=tmpfs,target=proc/1 true\n", ruleContainerPath},
	"target with a variable": {"FROM busybox\nRUN --mount=type=tmpfs,target=$T true\n", ruleMount},
	// Buildah reads a transport before the name, skipping the registry.
	"FROM containers-storage": {"FROM containers-storage:alpine\n", ruleTransport},
	"FROM docker-daemon":      {"FROM docker-daemon:alpine:3\n", ruleTransport},
	"FROM oci-archive":        {"FROM oci-archive:/tmp/x.tar\n", ruleTransport},
	"FROM oci upper case":     {"FROM OCI:/tmp/layout\n", ruleTransport},
	"FROM docker scheme":      {"FROM docker://attacker.example/evil\n", ruleTransport},
	"FROM dir":                {"FROM dir:/home/me/image\n", ruleTransport},
	"COPY from transport":     {"FROM busybox\nCOPY --from=containers-storage:alpine /a /b\n", ruleTransport},
	"FROM sif":                {"FROM sif:/tmp/x.sif AS s\n", ruleTransport},
}

// TestEngineEscapesRefused is the protection test for the final v0.2
// release pentest: each escape of an unpatched engine is refused.
func TestEngineEscapesRefused(t *testing.T) {
	for name, tt := range engineEscapes {
		t.Run(name, func(t *testing.T) {
			if _, _, rule := checkDockerfile([]byte(tt.file)); rule != tt.rule {
				t.Errorf("rule %q, want %q", rule, tt.rule)
			}
		})
	}
}

// TestContainerPathsAccepted keeps the check from refusing ordinary
// Dockerfiles: paths that only look like the kernel directories.
func TestContainerPathsAccepted(t *testing.T) {
	for _, file := range []string{
		"FROM busybox\nWORKDIR /app\nWORKDIR src\nWORKDIR ./lib/\n",
		"FROM busybox\nWORKDIR /srv/proc\nWORKDIR /device\nWORKDIR /system\nWORKDIR /app/dev\n",
		"FROM busybox\nWORKDIR /app/sub/..\n",
		"FROM busybox\nRUN --mount=type=tmpfs,target=/tmp/proc --mount=type=bind,source=x,target=cache true\n",
		"FROM docker:27-dind\nFROM registry.example:5000/team/app:1\n",
	} {
		if _, _, rule := checkDockerfile([]byte(file)); rule != "" {
			t.Errorf("%q refused (%s)", file, rule)
		}
	}
}

// pentestProblems reads a Dockerfile as BuildKit and Buildah could, with
// quotes and escapes dropped, and reports a WORKDIR or mount target in a
// kernel directory, a mount from another stage or image, or an image
// transport. It is the fuzz oracle's half for these rules.
func pentestProblems(data []byte) []string {
	var problems []string
	for _, line := range oracleLines(strings.TrimPrefix(string(data), "\xef\xbb\xbf")) {
		fields := buildkitSpace.Split(strings.Trim(line, "\t\v\f\r "), -1)
		keyword := strings.ToUpper(fields[0])
		flags := leadingFlags(fields[1:])
		for i, f := range fields[1:] {
			if keyword == "WORKDIR" && oracleKernelPath(f) {
				problems = append(problems, "workdir: "+line)
			}
			if keyword == "FROM" && i >= len(flags) && oracleTransport(f) {
				problems = append(problems, "transport: "+line)
			}
		}
		// Only leading flags are flags; a later --mount is a command word.
		for _, f := range flags {
			if strings.HasPrefix(strings.ToLower(f), "--from=") && oracleTransport(f) {
				problems = append(problems, "transport: "+line)
			}
			problems = append(problems, oracleMountProblems(keyword, f, line)...)
		}
	}
	return problems
}

func oracleMountProblems(keyword, flag, line string) []string {
	name, value, _ := strings.Cut(flag, "=")
	if keyword != "RUN" || !strings.EqualFold(name, "--mount") {
		return nil
	}
	var problems []string
	for _, kv := range strings.Split(strings.Trim(value, `"'`), ",") {
		k, v, _ := strings.Cut(strings.Trim(kv, `"'`), "=")
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "from":
			problems = append(problems, "mount from: "+line)
		case "target", "dst", "destination":
			if oracleKernelPath(v) {
				problems = append(problems, "mount target: "+line)
			}
		}
	}
	return problems
}

// oracleKernelPath unquotes and unescapes p; a variable could be anything.
func oracleKernelPath(p string) bool {
	p = strings.NewReplacer(`"`, "", "'", "", `\`, "").Replace(p)
	if strings.Contains(p, "$") {
		return true
	}
	first := strings.Split(strings.TrimPrefix(path.Clean("/"+p), "/"), "/")[0]
	clean := path.Clean(p)
	return slices.Contains([]string{"proc", "sys", "dev"}, first) || clean == ".." || strings.HasPrefix(clean, "../")
}

func oracleTransport(ref string) bool {
	ref = strings.TrimPrefix(strings.ToLower(ref), "--from=")
	prefix, _, ok := strings.Cut(ref, ":")
	return strings.Contains(ref, "://") || ok && slices.Contains([]string{"containers-storage", "docker-daemon", "oci", "oci-archive", "dir", "docker-archive", "sif", "tarball", "ostree"}, prefix)
}

// TestHardeningOracleCatchesOldCheck proves the oracle can fail: what the
// check accepted at 1d8a78b is caught by it.
func TestHardeningOracleCatchesOldCheck(t *testing.T) {
	for _, file := range []string{
		"FROM busybox\nWORKDIR /proc/self/fd/8\n",
		"FROM busybox AS s\nFROM busybox\nRUN --mount=type=bind,from=s,source=l,target=/h,rw true\n",
		"FROM busybox\nRUN --mount=type=tmpfs,target=/proc/1 true\n",
		"FROM containers-storage:alpine\n",
	} {
		if len(pentestProblems([]byte(file))) == 0 {
			t.Errorf("oracle missed %q", file)
		}
	}
}

// TestAppWorkdirChecked (final v0.2 release pentest): the image keeps its
// last WORKDIR and StartApp runs the app there, so a built image whose
// working directory is not a plain path outside /proc, /sys and /dev is
// refused, and the app always gets an explicit --workdir.
func TestAppWorkdirChecked(t *testing.T) {
	tests := map[string]struct {
		inspect, want, refused string
	}{
		"none":            {"null", "--workdir=/", ""},
		"empty":           {`""`, "--workdir=/", ""},
		"app":             {`"/app"`, "--workdir=/app", ""},
		"proc fd":         {`"/proc/self/fd/8"`, "", "workdir"},
		"dev":             {`"/dev/shm"`, "", "workdir"},
		"not clean":       {`"/app/../proc/1"`, "", "workdir"},
		"trailing slash":  {`"/app/"`, "", "workdir"},
		"relative":        {`"app"`, "", "workdir"},
		"space":           {`"/my app"`, "", "workdir"},
		"not a string":    {`{"a":1}`, "", "inspect"},
		"newline in path": {`"/app\n--privileged"`, "", "workdir"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			rec := withBuilds(networkRecorder(goodCanary, 0), 0)
			rec.workdir = tt.inspect
			s := testSandbox(t, rec)
			app, err := s.Build(context.Background(), dockerfileRepo(plainDockerfile))
			if err != nil {
				t.Fatal(err)
			}
			if tt.refused != "" {
				if app.Built() || app.Detail != tt.refused {
					t.Fatalf("Build = %+v, want refused %s", app, tt.refused)
				}
				return
			}
			if err := s.StartApp(context.Background(), app); err != nil {
				t.Fatalf("StartApp: %v", err)
			}
			runs := rec.to("run")
			if !slices.Contains(runs[len(runs)-1], tt.want) {
				t.Errorf("app run %q lacks %s", runs[len(runs)-1], tt.want)
			}
		})
	}
}

// TestStartAppNeedsCheckedWorkdir: an App made outside Build has no
// checked working directory and does not start.
func TestStartAppNeedsCheckedWorkdir(t *testing.T) {
	rec := withBuilds(networkRecorder(goodCanary, 0), 0)
	s := testSandbox(t, rec)
	app, err := s.Build(context.Background(), dockerfileRepo(plainDockerfile))
	if err != nil || !app.Built() {
		t.Fatalf("Build = %+v, %v", app, err)
	}
	if err := s.StartApp(context.Background(), App{Image: app.Image}); !errors.Is(err, ErrSpec) {
		t.Errorf("StartApp without a checked workdir: %v", err)
	}
	if err := s.StartApp(context.Background(), App{Image: app.Image, workdir: "/proc/self/fd/8"}); !errors.Is(err, ErrSpec) {
		t.Errorf("StartApp with a workdir in /proc: %v", err)
	}
}
