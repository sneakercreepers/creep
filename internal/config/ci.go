package config

import "strings"

// ciVars are well-known environment variables that mark a CI run when set
// to a value other than "", "0" or "false":
//   - CI: GitHub Actions, GitLab CI, CircleCI, Travis CI, Buildkite,
//     Bitbucket Pipelines, Drone, Woodpecker, AppVeyor
//   - TF_BUILD: Azure Pipelines
//   - JENKINS_URL: Jenkins
//   - TEAMCITY_VERSION: TeamCity
//   - CODEBUILD_BUILD_ID: AWS CodeBuild
//   - bamboo_buildKey: Bamboo
var ciVars = []string{"CI", "TF_BUILD", "JENKINS_URL", "TEAMCITY_VERSION", "CODEBUILD_BUILD_ID", "bamboo_buildKey"}

// providerVars are set by one CI provider each, never by hand, and mark a
// CI run whatever their value. A build step that runs before creep can
// append CI=false to $GITHUB_ENV (#116), but GitHub refuses to overwrite
// GITHUB_* there, so one falsy CI must not end detection.
var providerVars = []string{
	"GITHUB_ACTIONS",         // GitHub Actions
	"GITLAB_CI",              // GitLab CI
	"CIRCLECI",               // CircleCI
	"BUILDKITE",              // Buildkite
	"TRAVIS",                 // Travis CI
	"BITBUCKET_BUILD_NUMBER", // Bitbucket Pipelines
	"DRONE",                  // Drone
	"APPVEYOR",               // AppVeyor
}

// ciVarPairs mark a CI run only together: Google Cloud Build sets BUILD_ID
// and PROJECT_ID, and BUILD_ID alone is too common to rely on.
var ciVarPairs = [][2]string{{"BUILD_ID", "PROJECT_ID"}}

// InCI reports whether getenv describes a CI run: any of ciVars set to a
// value other than "", "0" or "false", any of providerVars set at all, or
// both variables of a ciVarPairs entry set. This is the one definition creep
// uses; in CI nothing may prompt and endpoint consent must come from the
// policy. A CI run this misses is still safe: with no stored consent and no
// terminal, the consent prompt declines without reading, and with a
// terminal nobody answers it times out, so nothing is sent.
func InCI(getenv func(string) string) bool {
	for _, name := range ciVars {
		if isSet(getenv(name)) {
			return true
		}
	}
	for _, name := range providerVars {
		if strings.TrimSpace(getenv(name)) != "" {
			return true
		}
	}
	for _, p := range ciVarPairs {
		if isSet(getenv(p[0])) && isSet(getenv(p[1])) {
			return true
		}
	}
	return false
}

func isSet(v string) bool {
	v = strings.ToLower(strings.TrimSpace(v))
	return v != "" && v != "0" && v != "false"
}
