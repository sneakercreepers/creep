package main

import (
	"regexp"
	"strings"
	"testing"
)

const (
	checkReadOnly   = "    permissions:\n      contents: read\n"
	checkTagPattern = `grep -Eqx 'v[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}'`
	checkCaller     = "  package-check:\n    needs: package-repos\n    if: github.event_name == 'push'\n" + checkReadOnly +
		"    uses: ./.github/workflows/package-check.yml # zizmor: ignore[self-repository] actionlint v1.7.12 refuses $/, and ./ is this commit's own workflow\n    with:\n      tag: ${{ github.ref_name }}\n"
)

// checkExpression is the only shape a ${{ }} may take in package-check.yml:
// a whole env, with or runs-on value, so no input reaches a run: script as text.
var checkExpression = regexp.MustCompile(`^ +(TAG|runs-on): \$\{\{ (inputs\.tag|matrix\.os) \}\}$`)

// Protection (#357, ADR 0033): the job that installs a published release from
// the tap and the bucket holds no secret and only contents: read, so a
// compromised tap, bucket or release asset meets a runner with nothing to
// steal or write; the dispatch tag is validated and reaches scripts only
// through env.
func TestPackageCheckReadOnly(t *testing.T) {
	release := strings.ReplaceAll(readRepoFile(t, ".github/workflows/release.yml"), "\r\n", "\n")
	check := strings.ReplaceAll(readRepoFile(t, ".github/workflows/package-check.yml"), "\r\n", "\n")
	if problem := packageCheckProblem(release, check); problem != "" {
		t.Fatal(problem)
	}
	tests := []struct{ name, file, old, repl, want string }{
		{"caller inherits secrets", "release.yml", "      tag: ${{ github.ref_name }}\n", "      tag: ${{ github.ref_name }}\n    secrets: inherit\n", "package-check job"},
		{"caller writes", "release.yml", checkCaller, strings.Replace(checkCaller, "contents: read", "contents: write", 1), "package-check job"},
		{"caller before the push", "release.yml", "    needs: package-repos\n", "    needs: release\n", "package-check job"},
		{"secret in the check", "package-check.yml", "      HOMEBREW_NO_ANALYTICS: \"1\"\n", "      HOMEBREW_NO_ANALYTICS: \"1\"\n      GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}\n", "secret"},
		{"github token in the check", "package-check.yml", "      HOMEBREW_NO_ANALYTICS: \"1\"\n", "      HOMEBREW_NO_ANALYTICS: \"1\"\n      GH_TOKEN: ${{ github.token }}\n", "secret"},
		{"check job writes", "package-check.yml", "  scoop:\n    needs: tag\n    runs-on: windows-latest\n    timeout-minutes: 20\n    permissions:\n      contents: read\n", "  scoop:\n    needs: tag\n    runs-on: windows-latest\n    timeout-minutes: 20\n    permissions:\n      contents: write\n", "contents: read"},
		{"check job gains a permission", "package-check.yml", "  scoop:\n    needs: tag\n    runs-on: windows-latest\n    timeout-minutes: 20\n    permissions:\n      contents: read\n", "  scoop:\n    needs: tag\n    runs-on: windows-latest\n    timeout-minutes: 20\n    permissions:\n      contents: read\n      id-token: write\n", "contents: read"},
		{"check job without permissions", "package-check.yml", "    timeout-minutes: 5\n    permissions:\n      contents: read\n", "    timeout-minutes: 5\n", "contents: read"},
		{"workflow default permissions", "package-check.yml", "\npermissions: {}\n", "\n", "permissions: {}"},
		{"input in a script", "package-check.yml", `[ "$got" != "creep $TAG" ]`, `[ "$got" != "creep ${{ inputs.tag }}" ]`, "${{"},
		{"tag not validated", "package-check.yml", checkTagPattern, "true", "validate"},
		{"install before validation", "package-check.yml", "  scoop:\n    needs: tag\n", "  scoop:\n", "needs: tag"},
		{"checkout keeps credentials", "package-check.yml", "    steps:\n      - name: Install Scoop\n", "    steps:\n      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1\n      - name: Install Scoop\n", "persist-credentials"},
		{"no Intel mac", "package-check.yml", "[macos-latest, macos-15-intel]", "[macos-latest]", "runners"},
		{"quarantine not checked", "package-check.yml", "xattr -p com.apple.quarantine", "true", "quarantine"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, c := release, check
			target := &c
			if tt.file == "release.yml" {
				target = &r
			}
			if !strings.Contains(*target, tt.old) {
				t.Fatalf("%s lacks %q", tt.file, tt.old)
			}
			*target = strings.Replace(*target, tt.old, tt.repl, 1)
			if problem := packageCheckProblem(r, c); !strings.Contains(problem, tt.want) {
				t.Fatalf("problem %q, want one naming %q", problem, tt.want)
			}
		})
	}
}

// packageCheckProblem says why the release's package-check caller or
// package-check.yml could reach a secret, write, or run an unvalidated tag.
func packageCheckProblem(release, check string) string {
	if !strings.Contains(release, checkCaller) || strings.Contains(release, "secrets: inherit") {
		return "release.yml: the package-check job must need package-repos, hold only contents: read and pass no secret"
	}
	if problem := checkTextProblem(check); problem != "" {
		return problem
	}
	jobs := len(jobHeader.FindAllString(check, -1))
	switch {
	case !strings.Contains(check, "\npermissions: {}\n"):
		return "package-check.yml must set permissions: {} at the top"
	case jobs != 3 || strings.Count(check, checkReadOnly) != jobs || strings.Count(check, "permissions:") != jobs+1:
		return "package-check.yml: each of its 3 jobs must hold exactly contents: read"
	case !strings.Contains(check, checkTagPattern):
		return "package-check.yml must validate the tag"
	case strings.Count(check, "    needs: tag\n") != 2:
		return "package-check.yml: the install jobs must have needs: tag"
	case !strings.Contains(check, "[macos-latest, macos-15-intel]") || !strings.Contains(check, "runs-on: windows-latest"):
		return "package-check.yml must run on the arm64 and Intel macOS runners and on Windows"
	case !strings.Contains(check, "xattr -p com.apple.quarantine"):
		return "package-check.yml must check the binary for com.apple.quarantine"
	}
	return ""
}

// checkTextProblem finds secrets, write scopes, uncredentialed checkouts and
// expressions outside the env and runs-on shapes.
func checkTextProblem(check string) string {
	lower := strings.ToLower(check)
	switch {
	case strings.Contains(lower, ": write"):
		return "package-check.yml: every job must hold only contents: read"
	case strings.Contains(lower, "secrets") || strings.Contains(lower, "github.token") || strings.Contains(lower, "token:"):
		return "package-check.yml must name no secret or token"
	case strings.Count(check, "actions/checkout@") != strings.Count(check, "persist-credentials: false"):
		return "package-check.yml: every checkout must set persist-credentials: false"
	}
	for _, line := range strings.Split(check, "\n") {
		if strings.Contains(line, "${{") && !checkExpression.MatchString(line) {
			return "package-check.yml: a ${{ }} may only be a whole env or runs-on value: " + line
		}
	}
	return ""
}
