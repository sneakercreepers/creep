package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

// rootAgents is the AGENTS.md compared without its Current state; every
// other policy file counts as changed whenever git lists it (#56).
const rootAgents = "AGENTS.md"

// stateHeading opens the AGENTS.md section updated after every merge. It runs
// to the next level-2 heading and is the only part of AGENTS.md that changes
// without an ADR: the loop, invariants and conventions do not.
const stateHeading = "## Current state"

// guardFiles are the policy guard's own code and the ADRs that set the loop,
// lowercase prefixes.
var guardFiles = []string{
	"internal/tools/prcheck/",
	"docs/adr/0002-", "docs/adr/0004-", "docs/adr/0005-", "docs/adr/0006-", "docs/adr/0018-",
}

// adrFile is a decision record; the template and dependencies.txt are not.
var adrFile = regexp.MustCompile(`^docs/adr/[0-9]{4}-[^/]+\.md$`)

// isPolicyPath reports whether p is a policy file or the guard that pins it;
// policyChanges compares the root AGENTS.md without its Current state first.
func isPolicyPath(p string) bool {
	lower := strings.ToLower(p)
	base := path.Base(lower)
	if policyNames[base] || hasDir(lower, policyDir) {
		return true
	}
	if path.Dir(lower) == "internal/tools/budget" && strings.HasPrefix(base, "policy") && strings.HasSuffix(base, ".go") {
		return true
	}
	for _, prefix := range guardFiles {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

// adrProblems fails a PR that changes the policy guard or a policy file but
// adds or modifies no ADR, so the loop changes only through a recorded
// decision (#56). baseAgents is AGENTS.md before the change.
func adrProblems(files []string, root, baseAgents string) ([]string, error) {
	changed, err := policyChanges(files, root, baseAgents)
	if err != nil || len(changed) == 0 || hasADR(files, root) {
		return nil, err
	}
	problems := make([]string, 0, len(changed))
	for _, f := range changed {
		problems = append(problems, fmt.Sprintf("%q changes the agent-loop policy but no ADR under docs/adr/ is added or modified", f))
	}
	return problems, nil
}

func policyChanges(files []string, root, baseAgents string) ([]string, error) {
	var changed []string
	for _, f := range files {
		if f != rootAgents {
			if isPolicyPath(f) {
				changed = append(changed, f)
			}
			continue
		}
		moved, err := agentsMoved(root, baseAgents)
		if err != nil {
			return nil, err
		}
		if moved {
			changed = append(changed, f+" (outside Current state)")
		}
	}
	return changed, nil
}

// agentsMoved reports whether AGENTS.md outside its Current state differs
// from the base. A deleted AGENTS.md, or a Current state heading missing or
// repeated on either side, counts as a change.
func agentsMoved(root, baseAgents string) (bool, error) {
	head, err := readRegular(filepath.Join(root, rootAgents))
	if errors.Is(err, fs.ErrNotExist) {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("read %s: %w", rootAgents, err)
	}
	before, okBefore := withoutState(baseAgents)
	after, okAfter := withoutState(string(head))
	return !okBefore || !okAfter || before != after, nil
}

// withoutState returns text minus the lines from stateHeading to the next
// level-2 heading. A heading planted inside Current state ends it early, so
// what follows that heading is compared like the rest of the file.
func withoutState(text string) (string, bool) {
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	start, count := 0, 0
	for i, line := range lines {
		if line == stateHeading {
			start, count = i, count+1
		}
	}
	if count != 1 {
		return "", false
	}
	end := len(lines)
	for i := start + 1; i < len(lines); i++ {
		if strings.HasPrefix(lines[i], "## ") {
			end = i
			break
		}
	}
	return strings.Join(append(lines[:start:start], lines[end:]...), "\n"), true
}

// hasADR reports whether the PR adds or modifies an ADR: a listed decision
// record that is still a regular file after the change, so deleting one
// does not count.
func hasADR(files []string, root string) bool {
	if !plainADRDir(root) {
		return false
	}
	for _, f := range files {
		if !adrFile.MatchString(f) || strings.HasPrefix(f, "docs/adr/0000-") {
			continue
		}
		info, err := os.Lstat(filepath.Join(root, filepath.FromSlash(f)))
		if err == nil && info.Mode().IsRegular() {
			return true
		}
	}
	return false
}

// plainADRDir reports whether docs/ and docs/adr/ are real directories: a
// symlinked one could make a deleted ADR look present.
func plainADRDir(root string) bool {
	for _, dir := range []string{"docs", "docs/adr"} {
		info, err := os.Lstat(filepath.Join(root, filepath.FromSlash(dir)))
		if err != nil || info.Mode().Type() != fs.ModeDir {
			return false
		}
	}
	return true
}

// readRegular reads name only when it is a regular file, so a symlink cannot
// point the check at another file.
func readRegular(name string) ([]byte, error) {
	info, err := os.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", name)
	}
	return readBounded(name)
}
