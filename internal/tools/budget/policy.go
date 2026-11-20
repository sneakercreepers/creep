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

// pentesterScope, releaseGate and pentesterIsolation pin ADR 0002 and ADR 0004:
// the pentester stays independent and gates each release and every external PR.
const pentesterScope = "The pentester runs once per version, over the whole version diff before the release is tagged, and on every pull request from an external contributor"

const releaseGate = "A confirmed Critical or High from the release pentest blocks the release"

const pentesterIsolation = "The pentester gets no shared context"

// sharedContext and auditorEscalation complete ADR 0002: the escalation is the
// backstop for a missing label, so dropping it must fail CI like the rest.
const sharedContext = "Developer, tester and auditor share context"

const auditorEscalation = "If the auditor sees security impact in an unlabeled change, it asks a maintainer to add the label"

const templateSkip = "the release pentest covers this change"

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
	"CONTRIBUTING.md":                  {agentLoop, sharedContext, pentesterIsolation, pentesterScope, releaseGate, auditorEscalation, "Changing or removing this loop needs an ADR", docsOnlyRule, auditorTriage},
	".github/PULL_REQUEST_TEMPLATE.md": {agentLoop, "no shared context", templateSkip},
	"CLAUDE.md":                        {"@AGENTS.md"},
}

// htmlComment hides text from readers, so phrases inside it do not count. A
// <!-- with no closing tag hides the rest of the file in Markdown, so it ends
// at the end of the text (#58).
var htmlComment = regexp.MustCompile(`(?s)<!--.*?(?:-->|\z)`)

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
		visible := htmlComment.ReplaceAllString(string(data), "")
		for _, phrase := range requiredPolicy[name] {
			if !strings.Contains(visible, phrase) {
				problems = append(problems, fmt.Sprintf("policy: %s must contain %q", name, phrase))
			}
		}
	}
	return problems, nil
}
