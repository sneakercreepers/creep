package recipe

import (
	"errors"
	"fmt"
	"strings"
)

// ErrSource means a recipe source, a pin or a policy pattern breaks the
// format: github.com/<owner>/<repo>@<40-hex commit> (ADR 0028). Its
// messages never quote the value.
var ErrSource = errors.New("recipe source refused")

// Bounds GitHub puts on owner and repository names.
const (
	maxOwnerBytes = 39
	maxRepoBytes  = 100
	commitHexLen  = 40
	sourceHost    = "github.com/"
)

// Source is a recipe repository pinned to one commit. Owner and Name are
// lower case: GitHub names are case-insensitive, so the lock and the
// policy compare one spelling.
type Source struct {
	Owner  string
	Name   string
	Commit string
}

// ParseSource reads github.com/<owner>/<repo>@<commit>. The commit must be
// a full 40-hex SHA-1: a branch, a tag or a short SHA names a commit that
// can move or collide, so they are refused.
func ParseSource(s string) (Source, error) {
	repo, commit, ok := strings.Cut(s, "@")
	if !ok {
		return Source{}, fmt.Errorf("%w: want github.com/<owner>/<repo>@<full 40-hex commit SHA>", ErrSource)
	}
	src, err := parseRepository(repo)
	if err != nil {
		return Source{}, err
	}
	if !validCommit(commit) {
		return Source{}, fmt.Errorf("%w: the pin must be a full 40-hex commit SHA in lower case; branch names, tags and short SHAs are refused", ErrSource)
	}
	src.Commit = commit
	return src, nil
}

// Repository is the source without its pin: github.com/<owner>/<repo>.
func (s Source) Repository() string { return sourceHost + s.Owner + "/" + s.Name }

// String is the pinned source as `creep recipe add` takes it.
func (s Source) String() string { return s.Repository() + "@" + s.Commit }

// parseRepository reads github.com/<owner>/<repo>, lower-cased.
func parseRepository(s string) (Source, error) {
	rest, ok := cutPrefixFold(s, sourceHost)
	if !ok {
		return Source{}, fmt.Errorf("%w: only github.com/<owner>/<repo> sources are supported", ErrSource)
	}
	owner, name, ok := strings.Cut(strings.ToLower(rest), "/")
	if !ok || !validOwner(owner) || !validRepoName(name) {
		return Source{}, fmt.Errorf("%w: want github.com/<owner>/<repo> with GitHub's owner and repository name rules", ErrSource)
	}
	return Source{Owner: owner, Name: name}, nil
}

func cutPrefixFold(s, prefix string) (string, bool) {
	if len(s) < len(prefix) || !strings.EqualFold(s[:len(prefix)], prefix) {
		return "", false
	}
	return s[len(prefix):], true
}

// validOwner follows GitHub: 1 to 39 letters, digits and "-", not
// starting with "-".
func validOwner(o string) bool {
	if o == "" || len(o) > maxOwnerBytes || o[0] == '-' {
		return false
	}
	for i := range len(o) {
		if c := o[i]; !lowerOrDigit(c) && c != '-' {
			return false
		}
	}
	return true
}

// validRepoName follows GitHub: 1 to 100 letters, digits, ".", "-" and
// "_", and not "." or "..", which would be path segments.
func validRepoName(n string) bool {
	if n == "" || len(n) > maxRepoBytes || n == "." || n == ".." {
		return false
	}
	for i := range len(n) {
		if c := n[i]; !lowerOrDigit(c) && c != '-' && c != '_' && c != '.' {
			return false
		}
	}
	return true
}

// validCommit reports a full SHA-1 commit ID in lower-case hex.
func validCommit(c string) bool {
	if len(c) != commitHexLen {
		return false
	}
	for i := range len(c) {
		if !isHex(c[i]) {
			return false
		}
	}
	return true
}

func isHex(c byte) bool { return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' }

// CheckAllowlist checks an org policy's recipe_sources: each entry is a
// repository (github.com/<owner>/<repo>) or every repository of an owner
// (github.com/<owner>/*). A pinned entry is refused: the policy names
// sources, the lock pins them.
func CheckAllowlist(patterns []string) error {
	for i, p := range patterns {
		if owner, ok := strings.CutSuffix(p, "/*"); ok {
			if rest, ok := cutPrefixFold(owner, sourceHost); ok && validOwner(strings.ToLower(rest)) {
				continue
			}
			return fmt.Errorf("%w: recipe_sources entry %d: want github.com/<owner>/* or github.com/<owner>/<repo>", ErrSource, i+1)
		}
		if _, err := parseRepository(p); err != nil {
			return fmt.Errorf("recipe_sources entry %d: %w", i+1, err)
		}
	}
	return nil
}

// Allowed reports whether the policy lets src be installed and loaded.
// enforced false means the policy sets no recipe_sources, so the operator
// decides alone; an enforced empty list allows nothing.
func Allowed(src Source, patterns []string, enforced bool) bool {
	if !enforced {
		return true
	}
	for _, p := range patterns {
		if owner, ok := strings.CutSuffix(p, "/*"); ok {
			if strings.EqualFold(owner, sourceHost+src.Owner) {
				return true
			}
			continue
		}
		if strings.EqualFold(p, src.Repository()) {
			return true
		}
	}
	return false
}
