package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// agentLoop is the contribution loop the maintainer made mandatory; removing it
// must fail CI so it can only change through an ADR and this file (CODEOWNERS).
const agentLoop = "developer → tester → pentester → auditor"

// docsOnlyRule is the one sanctioned shortcut, kept narrow so it cannot cover code.
const docsOnlyRule = "Documentation-only changes run only the auditor"

const auditorTriage = "The auditor triages every open finding"

// pentesterScope and releaseGate pin ADR 0004: the pentester gates each
// release and every external PR.
const pentesterScope = "The pentester runs once per version, over the whole version diff before the release is tagged, and on every pull request from an external contributor"

const releaseGate = "A confirmed Critical or High from the release pentest blocks the release"

// sharedContext, pentesterIsolation and auditorEscalation pin ADR 0002 as
// whole sentences, so a trailing clause cannot be dropped or bent (#101):
// AGENTS.md carries the long form, CONTRIBUTING.md the short one. The
// escalation is the backstop for a missing label.
const (
	sharedContext          = "Developer, tester and auditor share context (issue, diff, test output, earlier verdicts)."
	sharedContextShort     = "Developer, tester and auditor share context."
	pentesterIsolation     = "The pentester gets no shared context: only the issue, the diff and the repository, so its review stays independent."
	pentesterIsolationNote = "The pentester gets no shared context."
	auditorEscalation      = "If the auditor sees security impact in an unlabeled change, it asks a maintainer to add the label so the release pentest covers it."
)

// checkbox marks a phrase that must be a whole line of its own, so the
// template's promises cannot survive outside their checkbox (#101).
const checkbox = "- [ ] "

const (
	templateLoop = checkbox + "AI-assisted: ran the agent loop " + agentLoop + ". Tester verdict, security review and auditor decision:"
	templateSkip = checkbox + "External contributor: the pentester ran with no shared context. Maintainer PRs: skipped; the release pentest covers this change (ADR 0004)."
)

// maxPolicyBytes bounds reads so a huge policy file cannot stall CI.
const maxPolicyBytes = 1 << 20

// requiredPolicy maps each file to the phrases that keep the agent loop documented.
var requiredPolicy = map[string][]string{
	"AGENTS.md": {
		agentLoop,
		sharedContext,
		pentesterIsolation,
		pentesterScope,
		releaseGate,
		auditorEscalation,
		"Confirmed Critical or High blocks the merge",
		"Maximum 3 cycles",
		"Changing or removing this loop needs an ADR",
		docsOnlyRule,
		auditorTriage,
	},
	"CONTRIBUTING.md":                  {agentLoop, sharedContextShort, pentesterIsolationNote, pentesterScope, releaseGate, auditorEscalation, "Changing or removing this loop needs an ADR", docsOnlyRule, auditorTriage},
	".github/PULL_REQUEST_TEMPLATE.md": {templateLoop, templateSkip},
	"CLAUDE.md":                        {"@AGENTS.md"},
}

// htmlComment hides text from readers, so phrases inside it do not count. A
// <!-- with no closing tag hides the rest of the file in Markdown, so it ends
// at the end of the text (#58).
var htmlComment = regexp.MustCompile(`(?s)<!--.*?(?:-->|\z)`)

// linkDefinition is a link-reference definition such as `[//]: # (text)` or
// `[x]: <url> "title"`, which GitHub does not render (#101). It runs through
// the next blank line so a title on a following line is hidden too; a
// paragraph right after it with no blank line is dropped as well, which can
// only fail the guard, never pass it.
var linkDefinition = regexp.MustCompile(`(?m)^[ \t>]*\[(?:\\.|[^\\\]\n])+\]:.*(?:\n[ \t>]*\S.*)*`)

func policyProblems(cfg config) ([]string, error) {
	return checkPolicy(cfg.root, readPolicyFile)
}

// readPolicyFile reads root/name only when every component below root is a
// plain directory and the last a regular file: a symlink at any level, not
// only the last, could point the guard at another file (#58).
func readPolicyFile(root, name string) ([]byte, error) {
	path := root
	parts := strings.Split(name, "/")
	for i, part := range parts {
		path = filepath.Join(path, part)
		info, err := os.Lstat(path)
		if err != nil {
			return nil, err
		}
		last := i == len(parts)-1
		if last && !info.Mode().IsRegular() {
			return nil, fmt.Errorf("%s is not a regular file", path)
		}
		if !last && info.Mode().Type() != fs.ModeDir {
			return nil, fmt.Errorf("%s is not a plain directory", path)
		}
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, maxPolicyBytes))
}

// checkPolicy reports policy files that are missing or lost a required phrase.
func checkPolicy(root string, read func(root, name string) ([]byte, error)) ([]string, error) {
	names := make([]string, 0, len(requiredPolicy))
	for name := range requiredPolicy {
		names = append(names, name)
	}
	sort.Strings(names)
	var problems []string
	for _, name := range names {
		data, err := read(root, name)
		if errors.Is(err, fs.ErrNotExist) {
			problems = append(problems, fmt.Sprintf("policy: %s is missing", name))
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("policy %s: %w", name, err)
		}
		visible := linkDefinition.ReplaceAllString(htmlComment.ReplaceAllString(string(data), ""), "")
		for _, phrase := range requiredPolicy[name] {
			if !hasPhrase(visible, phrase) {
				problems = append(problems, fmt.Sprintf("policy: %s must contain %q", name, phrase))
			}
		}
	}
	return problems, nil
}

// hasPhrase reports whether text shows phrase; a checkbox phrase must be a
// whole unindented line, so it stays a top-level task item.
func hasPhrase(text, phrase string) bool {
	if !strings.HasPrefix(phrase, checkbox) {
		return strings.Contains(text, phrase)
	}
	for _, line := range strings.Split(text, "\n") {
		if strings.TrimRight(line, " \t\r") == phrase {
			return true
		}
	}
	return false
}
