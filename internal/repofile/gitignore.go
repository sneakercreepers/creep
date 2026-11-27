package repofile

import (
	"path"
	"strings"
)

// GitIgnore holds the patterns of one .gitignore or info/exclude file, in
// git's gitignore syntax: "#" comments, "!" negation, a trailing "/" for
// directories only, a "/" at the start or in the middle anchoring the
// pattern to the file's directory, "*", "?", "[...]" within a name and
// "**" across directories. It names no tool, language or directory: the
// repository's own patterns decide (#366).
type GitIgnore struct {
	base  string // repo-relative directory the patterns apply under; "." is the root
	rules []ignoreRule
}

type ignoreRule struct {
	segs     []string // pattern names, "/"-separated; a run of "**" is one
	negate   bool
	dirOnly  bool
	anchored bool // matched from base; otherwise against the last name only
}

// ParseGitIgnore parses data, the patterns of a file in the repo-relative
// directory base. A pattern git would refuse (a bad character class)
// matches nothing.
func ParseGitIgnore(base string, data []byte) GitIgnore {
	g := GitIgnore{base: base}
	for _, line := range strings.Split(string(data), "\n") {
		if r, ok := parseIgnoreLine(strings.TrimSuffix(line, "\r")); ok {
			g.rules = append(g.rules, r)
		}
	}
	return g
}

func parseIgnoreLine(line string) (ignoreRule, bool) {
	line = trimUnescapedSpaces(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return ignoreRule{}, false
	}
	var r ignoreRule
	if strings.HasPrefix(line, "!") {
		r.negate, line = true, line[1:]
	} else if strings.HasPrefix(line, `\!`) || strings.HasPrefix(line, `\#`) {
		line = line[1:]
	}
	if strings.HasSuffix(line, "/") {
		r.dirOnly, line = true, strings.TrimSuffix(line, "/")
	}
	r.anchored = strings.Contains(line, "/")
	line = strings.TrimPrefix(line, "/")
	if line == "" {
		return ignoreRule{}, false
	}
	for _, s := range strings.Split(line, "/") {
		if s == "**" && len(r.segs) > 0 && r.segs[len(r.segs)-1] == "**" {
			continue
		}
		s = strings.ReplaceAll(s, "[!", "[^")
		if _, err := path.Match(s, ""); err != nil {
			return ignoreRule{}, false
		}
		r.segs = append(r.segs, s)
	}
	return r, true
}

// trimUnescapedSpaces drops trailing spaces unless a backslash quotes one.
func trimUnescapedSpaces(line string) string {
	for strings.HasSuffix(line, " ") && !strings.HasSuffix(line, `\ `) {
		line = line[:len(line)-1]
	}
	return line
}

// Match reports whether a pattern matches the repo-relative slash path
// rel, a directory when dir is set, and if so whether the last matching
// pattern ignores it or, negated, takes it back. A path outside base
// matches nothing.
func (g GitIgnore) Match(rel string, dir bool) (matched, ignored bool) {
	sub := rel
	if g.base != "." {
		var ok bool
		if sub, ok = strings.CutPrefix(rel, g.base+"/"); !ok {
			return false, false
		}
	}
	names := strings.Split(sub, "/")
	for i := len(g.rules) - 1; i >= 0; i-- {
		r := g.rules[i]
		if r.dirOnly && !dir {
			continue
		}
		if r.matches(names) {
			return true, !r.negate
		}
	}
	return false, false
}

func (r ignoreRule) matches(names []string) bool {
	if !r.anchored {
		ok, _ := path.Match(r.segs[0], names[len(names)-1])
		return ok
	}
	return matchNames(r.segs, names)
}

// matchNames matches pattern names against path names by dynamic
// programming, so a pattern of many "**" costs len(segs)*len(names), never
// an exponential search. A "**" in the middle or at the start matches zero
// or more names; a trailing one matches one or more (everything inside).
func matchNames(segs, names []string) bool {
	next := make([]bool, len(names)+1) // row i+1: segs[i+1:] against names[j:]
	next[len(names)] = true
	cur := make([]bool, len(names)+1)
	for i := len(segs) - 1; i >= 0; i-- {
		for j := len(names); j >= 0; j-- {
			cur[j] = matchAt(segs, names, i, j, cur, next)
		}
		next, cur = cur, next
	}
	return next[0]
}

func matchAt(segs, names []string, i, j int, cur, next []bool) bool {
	rest := j < len(names)
	switch {
	case segs[i] == "**" && i == len(segs)-1:
		return rest
	case segs[i] == "**":
		return next[j] || rest && cur[j+1]
	case !rest:
		return false
	}
	ok, _ := path.Match(segs[i], names[j])
	return ok && next[j+1]
}
