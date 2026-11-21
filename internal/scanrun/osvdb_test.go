package scanrun

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/sneakercreepers/creep/internal/repofile"
)

// TestRunNeedsEveryLockfileEcosystem (#226): osv-scanner matches a
// lockfile only against its ecosystem's offline database, and a miss
// reports nothing, so a database without an ecosystem the repository uses
// is failed (the run is incomplete) and osv-scanner is not started.
func TestRunNeedsEveryLockfileEcosystem(t *testing.T) {
	tests := []struct {
		name    string
		files   []string // repository files
		db      []string // ecosystems with a non-empty all.zip
		empty   []string // ecosystems with an empty all.zip
		want    Outcome
		failure Failure
	}{
		{"npm lockfile, npm database", []string{"package-lock.json"}, []string{"npm"}, nil, Evaluated, FailNone},
		{"no lockfile at all", []string{"main.c"}, []string{"npm"}, nil, Evaluated, FailNone},
		{"go.mod without a Go database", []string{"go.mod"}, []string{"npm"}, nil, Failed, FailEcosystemDB},
		{"nested Cargo.lock without crates.io", []string{"package-lock.json", "services/api/Cargo.lock"}, []string{"npm"}, nil, Failed, FailEcosystemDB},
		{"requirements file by shape", []string{"requirements-dev.txt"}, []string{"npm"}, nil, Failed, FailEcosystemDB},
		{".NET deps file by shape", []string{"bin/App.deps.json"}, []string{"npm"}, nil, Failed, FailEcosystemDB},
		{"case variant of a lockfile name", []string{"GEMFILE.LOCK"}, []string{"npm"}, nil, Failed, FailEcosystemDB},
		{"every ecosystem present", []string{"go.mod", "web/yarn.lock", "Pipfile.lock"}, []string{"Go", "npm", "PyPI"}, nil, Evaluated, FailNone},
		{"an empty all.zip does not count", []string{"go.mod"}, []string{"npm"}, []string{"Go"}, Failed, FailEcosystemDB},
		{"lockfile inside .git is not scanned", []string{".git/Cargo.lock"}, []string{"npm"}, nil, Evaluated, FailNone},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			base := t.TempDir()
			repo := filepath.Join(base, "repo")
			mkdir(t, repo)
			for _, f := range tc.files {
				writeFile(t, filepath.Join(repo, filepath.FromSlash(f)), "x")
			}
			db := t.TempDir()
			for _, eco := range tc.db {
				writeFile(t, filepath.Join(db, "osv-scanner", eco, "all.zip"), "PK fake")
			}
			for _, eco := range tc.empty {
				writeFile(t, filepath.Join(db, "osv-scanner", eco, "all.zip"), "")
			}
			bin := installFake(t, base, "empty", "osv-scanner")
			got := Run(context.Background(), Job{Scanner: repofile.ScannerOSV, Bin: bin, Repo: repo, OSVDB: db, Limits: testLimits()})
			if got.Outcome != tc.want || got.Failure != tc.failure {
				t.Fatalf("Run = %+v, want outcome %d, failure %s", got, tc.want, tc.failure)
			}
			if started := ran(bin); started != (tc.want == Evaluated) {
				t.Errorf("started = %v, want %v", started, tc.want == Evaluated)
			}
		})
	}
}

// TestRepoEcosystemsFollowsNoLink: a lockfile reached only through a link
// is outside what the walk covers; osv-scanner's own walk decides it.
func TestRepoEcosystemsFollowsNoLink(t *testing.T) {
	base := t.TempDir()
	repo, outside := filepath.Join(base, "repo"), filepath.Join(base, "outside")
	mkdir(t, repo)
	writeFile(t, filepath.Join(outside, "go.mod"), "module x\n")
	linkDir(t, outside, filepath.Join(repo, "link"))
	got, failure := repoEcosystems(context.Background(), repo)
	if failure != FailNone || len(got) != 0 {
		t.Errorf("repoEcosystems = %v, %s; want none", got, failure)
	}
}

// TestRepoEcosystemsStopsOnContext: a canceled walk is a timeout, never
// a clean "no lockfile".
func TestRepoEcosystemsStopsOnContext(t *testing.T) {
	repo := t.TempDir()
	writeFile(t, filepath.Join(repo, "go.mod"), "module x\n")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, failure := repoEcosystems(ctx, repo); failure != FailTimeout {
		t.Errorf("failure %s, want %s", failure, FailTimeout)
	}
}
