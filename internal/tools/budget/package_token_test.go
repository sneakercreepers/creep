package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const (
	packageTokenRef  = "${{ secrets.PACKAGE_REPOS_TOKEN }}" //nolint:gosec // G101: a workflow expression naming the secret, not a credential
	packagePushStep  = "      - name: Update the Homebrew tap and Scoop bucket\n        env:\n          PACKAGE_REPOS_TOKEN: " + packageTokenRef + "\n        run: bash .github/scripts/package-repos.sh \"$GITHUB_REF_NAME\" dist\n"
	packageVerifyRun = "--bundle dist/checksums.txt.sigstore.json dist/checksums.txt\n"
)

var jobHeader = regexp.MustCompile(`\n  [a-z][a-z0-9-]*:\n`)

// Protection (#344, ADR 0033, v0.5 release review R1, A2): the token that
// writes the Homebrew tap and the Scoop bucket lives only in the `release`
// environment and reaches only the push step of its own job, on a runner
// that never ran goreleaser, after that job re-verified checksums.txt.
// goreleaser never gets it and never uploads the cask or the manifest.
func TestPackageReposTokenOnlyInPushStep(t *testing.T) {
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
	config := strings.ReplaceAll(readRepoFile(t, ".goreleaser.yaml"), "\r\n", "\n")
	if problem := packageTokenProblem(release, config); problem != "" {
		t.Fatal(problem)
	}
	tests := []struct{ name, file, old, repl, want string }{
		{"token in the release job", "release.yml", "      - uses: actions/upload-artifact@", "      - name: x\n        env:\n          T: " + packageTokenRef + "\n      - uses: actions/upload-artifact@", "exactly once"},
		{"token on the verify step", "release.yml", "          GH_TOKEN: ${{ github.token }}\n        run: |\n          gh release download", "          GH_TOKEN: " + packageTokenRef + "\n        run: |\n          gh release download", "exactly once"},
		{"push step outside its job", "release.yml", "      - name: Update the Homebrew tap and Scoop bucket\n", "  other:\n    steps:\n      - name: Update the Homebrew tap and Scoop bucket\n", "package-repos job has no push step"},
		{"all secrets elsewhere", "release.yml", "GITHUB_TOKEN: ${{ github.token }}", "GITHUB_TOKEN: ${{ toJSON(secrets) }}", "toJSON(secrets"},
		{"indexed secret elsewhere", "release.yml", "GITHUB_TOKEN: ${{ github.token }}", "GITHUB_TOKEN: ${{ secrets['PACKAGE_REPOS_TOKEN'] }}", "secrets["},
		{"push job without the environment", "release.yml", "    needs: release\n    if: github.event_name == 'push'\n    runs-on: ubuntu-latest\n    environment: release\n", "    needs: release\n    if: github.event_name == 'push'\n    runs-on: ubuntu-latest\n", "release environment"},
		{"push job before the release", "release.yml", "    needs: release\n", "    needs: ancestry\n", "needs: release"},
		{"push job runs goreleaser", "release.yml", "      - uses: actions/download-artifact@", "      - run: bash .github/scripts/release-tools.sh\n      - uses: actions/download-artifact@", "goreleaser"},
		{"push without re-verifying", "release.yml", packageVerifyRun, "--help\n", "verify-blob"},
		{"push job writes", "release.yml", "      contents: read # the push script", "      contents: write # the push script", "contents: read"},
		{"goreleaser uploads the cask", ".goreleaser.yaml", "    skip_upload: true\n", "    skip_upload: false\n", "skip_upload"},
		{"goreleaser holds a token", ".goreleaser.yaml", "      name: scoop-bucket\n", "      name: scoop-bucket\n      token: x\n", "skip_upload"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, c := release, config
			target := &r
			if tt.file == ".goreleaser.yaml" {
				target = &c
			}
			if !strings.Contains(*target, tt.old) {
				t.Fatalf("%s lacks %q", tt.file, tt.old)
			}
			*target = strings.Replace(*target, tt.old, tt.repl, 1)
			if problem := packageTokenProblem(r, c); !strings.Contains(problem, tt.want) {
				t.Fatalf("problem %q, want one naming %q", problem, tt.want)
			}
		})
	}
}

// packageTokenProblem says why release.yml or .goreleaser.yaml would let the
// token reach more than the push step, or "" when they do not.
func packageTokenProblem(release, config string) string {
	switch {
	case strings.Count(release, "secrets.PACKAGE_REPOS_TOKEN") != 1 || strings.Count(release, "PACKAGE_REPOS_TOKEN: "+packageTokenRef) != 1:
		return "release.yml must pass secrets.PACKAGE_REPOS_TOKEN exactly once, as a step env"
	case strings.Contains(strings.ToLower(release), "tojson(secrets"):
		return "release.yml passes toJSON(secrets), which holds the token"
	case strings.Contains(release, "secrets["):
		return "release.yml indexes secrets[...], which can name the token"
	case strings.Count(config, "    skip_upload: true\n") != 2 || strings.Contains(config, "token:"):
		return ".goreleaser.yaml: the cask and the manifest must both set skip_upload: true and no token"
	}
	return pushJobProblem(release)
}

// pushJobProblem checks the package-repos job: it alone holds the push step,
// in the release environment, after the release job, read-only, without
// goreleaser, and only after it verified checksums.txt's signature.
func pushJobProblem(release string) string {
	start := strings.Index(release, "\n  package-repos:\n")
	if start < 0 {
		return "release.yml: no package-repos job"
	}
	job := release[start+1:]
	if end := jobHeader.FindStringIndex(job); end != nil {
		job = job[:end[0]+1]
	}
	at := strings.Index(job, packagePushStep)
	switch {
	case at < 0:
		return "release.yml: the package-repos job has no push step holding PACKAGE_REPOS_TOKEN"
	case !strings.Contains(job, "    needs: release\n"):
		return "release.yml: the package-repos job must declare needs: release"
	case !strings.Contains(job, "    environment: release\n"):
		return "release.yml: the package-repos job does not run in the release environment"
	case !strings.Contains(job, "    permissions:\n      contents: read #"):
		return "release.yml: the package-repos job must hold only contents: read"
	case strings.Contains(job, "goreleaser") || strings.Contains(job, "release-tools.sh") || strings.Contains(job, "setup-go"):
		return "release.yml: the package-repos job must not run goreleaser or its tools"
	case !strings.Contains(job[:at], packageVerifyRun):
		return "release.yml: the package-repos job must cosign verify-blob checksums.txt before the push step"
	}
	return ""
}
