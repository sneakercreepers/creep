package sandbox

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"testing"
)

// secretPaths are repository files that must never reach a builder.
var secretPaths = []string{
	".env", ".env.local", "config/.env.production", ".ENV", ".envrc",
	".git/config", ".git/hooks/pre-commit", ".creep/state.jsonl",
	".ssh/id_ed25519", "home/.aws/credentials", ".azure/token", ".kube/config", ".gnupg/key",
	".netrc", "_netrc", ".git-credentials", ".npmrc", ".pypirc",
}

// TestBuildContextLeavesSecretsOut is the protection test for the build
// context: the builder gets a copy made in the work directory from the
// scan's reader, holding the context's clean paths only, without .env
// files, git or creep state or credential files, and never anything a
// path names outside the repository. The check is proven to catch a
// context that holds a secret.
func TestBuildContextLeavesSecretsOut(t *testing.T) {
	files := map[string]string{"Dockerfile": plainDockerfile, "app.py": "print(1)\n", "run.sh": "#!/bin/sh\necho\n", "web/index.js": ""}
	for _, p := range secretPaths {
		files[p] = "SECRET=hunter2\n"
	}
	m := &memRepo{files: files}
	repo := m.repo()
	repo.Paths = append(repo.Paths, "../outside", "/etc/passwd", "a/../../b", `a\b`, "./app.py", "")
	s := testSandbox(t, &recorder{})
	dir, why := s.stageContext(repo, buildPlan{context: ".", dockerfile: "Dockerfile"})
	if why != nil {
		t.Fatalf("refused: %+v", why)
	}
	if p := contextProblems(t, s, dir); len(p) > 0 {
		t.Errorf("context: %v", p)
	}
	got := stagedFiles(t, dir)
	if want := []string{"Dockerfile", "app.py", "run.sh", "web/index.js"}; !slices.Equal(got, want) {
		t.Errorf("staged %q, want %q", got, want)
	}
	for _, p := range m.read {
		if leftOut(p) {
			t.Errorf("read %q, which never enters a context", p)
		}
	}
	if runtime.GOOS != "windows" {
		if info, err := os.Stat(filepath.Join(dir, "run.sh")); err != nil || info.Mode().Perm()&0o100 == 0 {
			t.Errorf("script not executable: %v %v", info, err)
		}
	}
	// The check can fail: a context holding a secret is caught.
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if len(contextProblems(t, s, dir)) == 0 {
		t.Error("a context holding .env passed the check")
	}
}

// contextProblems checks a staged context: inside the work directory, and
// no left-out name anywhere in it.
func contextProblems(t *testing.T, s *Sandbox, dir string) []string {
	t.Helper()
	var problems []string
	if rel, err := filepath.Rel(s.work, dir); err != nil || !filepath.IsLocal(rel) {
		problems = append(problems, "context outside the work directory: "+dir)
	}
	for _, p := range stagedFiles(t, dir) {
		if leftOut(p) {
			problems = append(problems, "holds "+p)
		}
	}
	return problems
}

func stagedFiles(t *testing.T, dir string) []string {
	t.Helper()
	var files []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		files = append(files, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(files)
	return files
}

func TestStageContextOfSubdirectory(t *testing.T) {
	m := &memRepo{files: map[string]string{"web/Dockerfile": plainDockerfile, "web/a/b.txt": "b", "web/.env": "x", "api/main.go": "", "webby/x": ""}}
	s := testSandbox(t, &recorder{})
	dir, why := s.stageContext(m.repo(), buildPlan{context: "web", dockerfile: "web/Dockerfile"})
	if why != nil {
		t.Fatalf("refused: %+v", why)
	}
	if got := stagedFiles(t, dir); !slices.Equal(got, []string{"Dockerfile", "a/b.txt"}) {
		t.Errorf("staged %q", got)
	}
}

func TestStageContextRefuses(t *testing.T) {
	many := map[string]string{}
	for i := range maxContextFiles + 1 {
		many["f/"+strconv.Itoa(i)] = ""
	}
	limit := maxContextBytes
	maxContextBytes = 1 << 10
	t.Cleanup(func() { maxContextBytes = limit })
	tests := map[string]struct {
		repo   Repo
		detail string
	}{
		"too many files": {(&memRepo{files: many}).repo(), "too_many_files"},
		"too large": {Repo{Paths: []string{"a", "b", "c"}, Read: func(string) ([]byte, error) {
			return make([]byte, 400), nil
		}}, "too_large"},
		"unreadable":   {Repo{Paths: []string{"a"}, Read: func(string) ([]byte, error) { return nil, errors.New("fifo") }}, "unreadable_file"},
		"file and dir": {(&memRepo{files: map[string]string{"a": "", "a/b": ""}}).repo(), "write"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			s := testSandbox(t, &recorder{})
			_, why := s.stageContext(tt.repo, buildPlan{context: "."})
			if why == nil || why.reason != BuildContextRefused || why.detail != tt.detail {
				t.Errorf("got %+v, want %s", why, tt.detail)
			}
		})
	}
}
