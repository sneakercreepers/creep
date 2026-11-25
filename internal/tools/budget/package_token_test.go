package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Protection (#344, ADR 0033): the token that writes the Homebrew tap and
// the Scoop bucket lives only in the `release` environment and reaches only
// the step that pushes the cask and the manifest, after the release is
// verified and public. goreleaser never gets it and never uploads them.
func TestPackageReposTokenOnlyInPushStep(t *testing.T) {
	const ref = "${{ secrets.PACKAGE_REPOS_TOKEN }}"
	workflows, err := filepath.Glob(filepath.Join(repoRoot, ".github", "workflows", "*.y*ml"))
	if err != nil || len(workflows) == 0 {
		t.Fatalf("no workflows found: %v", err)
	}
	for _, path := range workflows {
		data, err := os.ReadFile(path) //nolint:gosec // G304: the repository's own workflows
		if err != nil {
			t.Fatal(err)
		}
		if filepath.Base(path) != "release.yml" && strings.Contains(string(data), "PACKAGE_REPOS_TOKEN") {
			t.Errorf("%s names PACKAGE_REPOS_TOKEN; only release.yml may", filepath.Base(path))
		}
	}
	release := strings.ReplaceAll(readRepoFile(t, ".github/workflows/release.yml"), "\r\n", "\n")
	if n := strings.Count(release, "PACKAGE_REPOS_TOKEN: "+ref); n != 1 || strings.Count(release, "secrets.PACKAGE_REPOS_TOKEN") != 1 {
		t.Fatalf("release.yml must pass secrets.PACKAGE_REPOS_TOKEN exactly once, as a step env (found %d)", n)
	}
	start := strings.Index(release, "\n  release:\n")
	if start < 0 {
		t.Fatal("release.yml: no release job")
	}
	checkPushStep(t, release[start:])
	config := readRepoFile(t, ".goreleaser.yaml")
	if n := strings.Count(config, "    skip_upload: true\n"); n != 2 || strings.Contains(config, "token:") {
		t.Errorf(".goreleaser.yaml: the cask and the manifest must both set skip_upload: true and no token (found %d)", n)
	}
}

// checkPushStep fails unless the token sits in the push step of the release
// job, which needs the `release` environment and runs after publishing.
func checkPushStep(t *testing.T, job string) {
	t.Helper()
	step := "      - name: Update the Homebrew tap and Scoop bucket\n        env:\n          PACKAGE_REPOS_TOKEN: ${{ secrets.PACKAGE_REPOS_TOKEN }}\n        run: bash .github/scripts/package-repos.sh \"$GITHUB_REF_NAME\" dist\n"
	at := strings.Index(job, step)
	if at < 0 {
		t.Fatal("release.yml: the release job has no push step holding PACKAGE_REPOS_TOKEN")
	}
	if !strings.Contains(job[:at], "    environment: release\n") {
		t.Error("release.yml: the push step's job does not run in the release environment")
	}
	if !strings.Contains(job[:at], "      - name: Publish the release\n") {
		t.Error("release.yml: the push step must come after the release is published")
	}
}
