package recipe

import (
	"bufio"
	"bytes"
	"strings"
)

// The operator's clone (ADR 0028): creep never fetches a recipe. The
// operator clones the source with git and checks out the pinned commit;
// creep reads only the clone's .git/HEAD and .git/config to check that the
// clone is that commit of that repository. It never runs git.

// Bounds on the git files creep reads from a clone.
const (
	MaxHeadBytes      = 256
	MaxGitConfigBytes = 64 << 10
)

// DetachedHead returns the commit a .git/HEAD file names, when HEAD is
// detached: one full lower-case SHA-1 and a newline. A symbolic HEAD
// ("ref: refs/heads/main") is a branch, which can move, so it is refused.
func DetachedHead(data []byte) (string, bool) {
	commit := strings.TrimSuffix(string(data), "\n")
	return commit, validCommit(commit)
}

// OriginRepository returns github.com/<owner>/<repo>, lower case, for the
// url of [remote "origin"] in a .git/config file, or false when there is
// no such remote or it is not a GitHub repository URL creep reads.
func OriginRepository(gitConfig []byte) (string, bool) {
	url, ok := originURL(gitConfig)
	if !ok {
		return "", false
	}
	src, err := parseRepository(githubPath(url))
	if err != nil {
		return "", false
	}
	return src.Repository(), true
}

// originURL is the first url key of the [remote "origin"] section.
func originURL(gitConfig []byte) (string, bool) {
	in := false
	sc := bufio.NewScanner(bytes.NewReader(gitConfig))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "[") {
			in = isOriginSection(line)
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if in && ok && strings.EqualFold(strings.TrimSpace(key), "url") {
			return strings.Trim(strings.TrimSpace(value), `"`), true
		}
	}
	return "", false
}

// isOriginSection reports a [remote "origin"] header: the section name is
// case-insensitive in git, the subsection is not.
func isOriginSection(line string) bool {
	name, sub, ok := strings.Cut(strings.TrimSuffix(strings.TrimPrefix(line, "["), "]"), " ")
	return ok && strings.EqualFold(name, "remote") && strings.TrimSpace(sub) == `"origin"`
}

// githubPath turns the GitHub URL forms git clone takes into
// github.com/<owner>/<repo>: https://github.com/o/r(.git),
// git@github.com:o/r(.git) and ssh://git@github.com/o/r(.git). Anything
// else comes back as it is and fails parseRepository.
func githubPath(url string) string {
	rest := url
	for _, prefix := range []string{"https://", "ssh://git@", "git@"} {
		if r, ok := strings.CutPrefix(rest, prefix); ok {
			rest = r
			break
		}
	}
	rest = strings.Replace(rest, "github.com:", "github.com/", 1)
	rest = strings.TrimSuffix(rest, "/")
	return strings.TrimSuffix(rest, ".git")
}
