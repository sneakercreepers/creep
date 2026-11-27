package testapps

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"
)

// liveApps are the apps that really serve in the sandbox (#364): the
// framework is installed at build time, offline, from wheels committed
// beside the source, and the compose file names the app's migrate step.
// Each extra file is fixed here, so a change to what runs at build time
// or which binary is installed is a change to this test, and review sees
// it: the Dockerfile and compose file byte for byte, requirements.txt as
// pinned name==version lines with a SHA-256 each, and wheels/ holding
// exactly one file per pin, with that digest. Still nothing executes the
// apps outside the sandbox (TestNothingExecutesApps), and the go command
// never builds them.
var liveApps = map[string]bool{"flaskpg": true}

const (
	liveDockerfile = "FROM docker.io/library/python@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90\n" +
		"ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1\n" +
		"WORKDIR /app\n" +
		"COPY requirements.txt ./\n" +
		"COPY wheels ./wheels\n" +
		"RUN pip install --no-index --find-links=/app/wheels --require-hashes -r requirements.txt\n" +
		"COPY . .\n" +
		"RUN mkdir -p /app/uploads\n" +
		"EXPOSE 8000\n" +
		"CMD [\"python\", \"app.py\"]\n"
	liveCompose = "services:\n" +
		"  app:\n    build: .\n    ports:\n      - \"8000:8000\"\n    env_file: .env\n" +
		"  migrate:\n    build: .\n    command: [\"python\", \"migrate.py\"]\n    env_file: .env\n"
	requirementsFile = "requirements.txt"
	wheelsDir        = "wheels"
	composeFile      = "compose.yaml"
)

// pin is one requirements.txt line pip installs with --require-hashes.
var pin = regexp.MustCompile(`^([a-z0-9][a-z0-9.-]*)==([0-9][A-Za-z0-9.]*) --hash=sha256:([0-9a-f]{64})$`)

// checkLiveEntry checks a live app's extra entry. ok is false for any
// other entry, which the source rules then check.
func checkLiveEntry(fsys fs.FS, dir string, e fs.DirEntry, live bool) (problems []string, ok bool) {
	if !live {
		return nil, false
	}
	name := path.Join(dir, e.Name())
	switch e.Name() {
	case buildFile:
		return exactFile(fsys, name, e, liveDockerfile), true
	case composeFile:
		return exactFile(fsys, name, e, liveCompose), true
	case requirementsFile:
		return checkPins(fsys, dir), true
	case wheelsDir:
		if !e.IsDir() {
			return []string{name + ": wheels/ must be a directory"}, true
		}
		return nil, true
	}
	return nil, false
}

func exactFile(fsys fs.FS, name string, e fs.DirEntry, want string) []string {
	if !e.Type().IsRegular() {
		return []string{name + ": only regular files (no directories or symlinks)"}
	}
	data, err := fs.ReadFile(fsys, name)
	if err != nil {
		return []string{fmt.Sprintf("%s: %v", name, err)}
	}
	if string(data) != want {
		return []string{name + ": a live app's build files must be exactly the pinned ones"}
	}
	return nil
}

// checkPins reads requirements.txt and wheels/: every pin has exactly one
// wheel of that name and version whose digest matches, and wheels/ holds
// nothing else.
func checkPins(fsys fs.FS, dir string) []string {
	data, err := fs.ReadFile(fsys, path.Join(dir, requirementsFile))
	if err != nil {
		return []string{fmt.Sprintf("%s/%s: %v", dir, requirementsFile, err)}
	}
	want, problems := parsePins(dir, data)
	entries, err := fs.ReadDir(fsys, path.Join(dir, wheelsDir))
	if err != nil {
		return append(problems, fmt.Sprintf("%s/%s: %v", dir, wheelsDir, err))
	}
	var got []string
	for _, e := range entries {
		wheel := path.Join(dir, wheelsDir, e.Name())
		if p := checkWheel(fsys, wheel, e, want); p != "" {
			problems = append(problems, p)
			continue
		}
		got = append(got, e.Name())
	}
	if len(got) != len(want) {
		problems = append(problems, fmt.Sprintf("%s: %d wheels for %d pins", dir, len(got), len(want)))
	}
	return problems
}

// parsePins maps "name-version" to its digest; comments and blank lines
// are allowed, anything else is a problem.
func parsePins(dir string, data []byte) (map[string]string, []string) {
	pins := map[string]string{}
	var problems []string
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		m := pin.FindStringSubmatch(line)
		if m == nil {
			problems = append(problems, fmt.Sprintf("%s/%s: %q is not a pinned name==version --hash=sha256 line", dir, requirementsFile, line))
			continue
		}
		pins[wheelKey(m[1], m[2])] = m[3]
	}
	return pins, problems
}

// wheelKey is how a wheel file names a project: lower case, "-" and "."
// as "_" (PEP 427), then its version.
func wheelKey(name, version string) string {
	return strings.NewReplacer("-", "_", ".", "_").Replace(strings.ToLower(name)) + "-" + version
}

func checkWheel(fsys fs.FS, wheel string, e fs.DirEntry, pins map[string]string) string {
	parts := strings.SplitN(e.Name(), "-", 3)
	if !e.Type().IsRegular() || path.Ext(e.Name()) != ".whl" || len(parts) != 3 {
		return wheel + ": wheels/ holds only regular .whl files"
	}
	digest, ok := pins[wheelKey(parts[0], parts[1])]
	if !ok {
		return wheel + ": no requirements.txt pin names this wheel"
	}
	data, err := fs.ReadFile(fsys, wheel)
	if err != nil {
		return fmt.Sprintf("%s: %v", wheel, err)
	}
	if sum := sha256.Sum256(data); hex.EncodeToString(sum[:]) != digest {
		return wheel + ": its SHA-256 is not the pinned one"
	}
	return ""
}

// liveFS is a live app "flaskpg" whose variants hold the pinned build
// files and one wheel, changed by extra as in appFS.
func liveFS(extra fstest.MapFS) fstest.MapFS {
	wheel := []byte("PK wheel bytes")
	sum := sha256.Sum256(wheel)
	pins := "# offline\nflask==3.1.2 --hash=sha256:" + hex.EncodeToString(sum[:]) + "\n"
	fsys := fstest.MapFS{"flaskpg/expected.json": {Data: []byte(strings.Replace(goodExpected, `"app":"x"`, `"app":"flaskpg"`, 1))}}
	for _, v := range variants {
		dir := "flaskpg/" + v + "/"
		fsys[dir+"app.py"] = &fstest.MapFile{Data: []byte(goodSource)}
		fsys[dir+buildFile] = &fstest.MapFile{Data: []byte(liveDockerfile)}
		fsys[dir+composeFile] = &fstest.MapFile{Data: []byte(liveCompose)}
		fsys[dir+requirementsFile] = &fstest.MapFile{Data: []byte(pins)}
		fsys[dir+"wheels/flask-3.1.2-py3-none-any.whl"] = &fstest.MapFile{Data: wheel}
	}
	for k, v := range extra {
		if v == nil {
			delete(fsys, k)
			continue
		}
		fsys[k] = v
	}
	return fsys
}

// TestCheckLiveApp: a live app holds only the pinned build files, pins
// and wheels besides its source; any other build step, compose content,
// unpinned requirement, unlisted or altered wheel is a problem, and an
// app that is not live may hold none of them.
func TestCheckLiveApp(t *testing.T) {
	const v = "flaskpg/vulnerable/"
	tests := []struct {
		name  string
		extra fstest.MapFS
		want  string
	}{
		{"good", nil, ""},
		{"dockerfile that runs more", fstest.MapFS{v + buildFile: {Data: []byte(liveDockerfile + "RUN python app.py\n")}}, "exactly the pinned"},
		{"compose that mounts the host", fstest.MapFS{v + composeFile: {Data: []byte(liveCompose + "    volumes: [\"/:/host\"]\n")}}, "exactly the pinned"},
		{"unpinned requirement", fstest.MapFS{v + requirementsFile: {Data: []byte("flask\n")}}, "not a pinned"},
		{"index option", fstest.MapFS{v + requirementsFile: {Data: []byte("--index-url https://example.invalid\n")}}, "not a pinned"},
		{"altered wheel", fstest.MapFS{v + "wheels/flask-3.1.2-py3-none-any.whl": {Data: []byte("other bytes")}}, "not the pinned one"},
		{"unlisted wheel", fstest.MapFS{v + "wheels/evil-1.0-py3-none-any.whl": {Data: []byte("x")}}, "no requirements.txt pin"},
		{"missing wheel", fstest.MapFS{v + "wheels/flask-3.1.2-py3-none-any.whl": nil, v + "wheels/README": {Data: []byte("x")}}, "only regular .whl"},
		{"script in wheels", fstest.MapFS{v + "wheels/install.sh": {Data: []byte("x")}}, "only regular .whl"},
		{"wheels as a file", fstest.MapFS{v + "wheels/flask-3.1.2-py3-none-any.whl": nil, v + wheelsDir: {Data: []byte("x")}}, "must be a directory"},
		{"dockerfile link", fstest.MapFS{v + buildFile: {Data: []byte("app.py"), Mode: fs.ModeSymlink}}, "regular files"},
		{"other manifest", fstest.MapFS{v + "pyproject.toml": {Data: []byte("x")}}, "only .py"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertProblems(t, checkApp(liveFS(tt.extra), "flaskpg"), tt.want)
		})
	}
	notLive := appFS(goodExpected, fstest.MapFS{"x/vulnerable/" + requirementsFile: {Data: []byte("x")}})
	assertProblems(t, checkApp(notLive, "x"), "only .py")
}
