package main

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// htmlComment hides text from readers. A <!-- with no closing tag hides the
// rest of the body in Markdown, so it ends at the end of the text.
var htmlComment = regexp.MustCompile(`(?s)<!--.*?(?:-->|\z)`)

// taskItem matches a task-list item; group 1 is the box, group 2 the text.
var taskItem = regexp.MustCompile(`^\s*(?:[-*+]|\d{1,9}[.)])\s+\[([ xX])\]\s*(.*)$`)

// listItem starts any list item, which ends the previous item's text.
var listItem = regexp.MustCompile(`^\s*(?:[-*+]|\d{1,9}[.)])\s`)

// commentLink is a link to a comment, review or review comment on a PR.
var commentLink = regexp.MustCompile(`https://github\.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)/(?:pull|issues)/(\d+)#(?:issuecomment-\d+|pullrequestreview-\d+|discussion_r\d+)`)

// box is a loop checkbox the body can tick.
type box int

const (
	noBox box = iota
	loopBox
	externalBox
	docsBox
)

// boxPrefixes are lowercase, after emphasis and code marks are removed.
// "ai-assisted:" leaves out the "AI-assisted (tool/model: …)" declaration.
var boxPrefixes = []struct {
	prefix string
	box    box
}{
	{"ai-assisted:", loopBox},
	{"external contributor", externalBox},
	{"documentation-only", docsBox},
}

// pullRequest is what the body checks need from the event payload.
type pullRequest struct {
	repo   string
	number int
	body   string
}

// tickedItems returns the visible text of each ticked task item, with its
// continuation lines, keyed by the loop box it names.
func tickedItems(body string) map[box][]string {
	visible := htmlComment.ReplaceAllString(strings.ReplaceAll(body, "\r\n", "\n"), "")
	items := map[box][]string{}
	current := -1
	var texts []string
	for _, line := range strings.Split(visible, "\n") {
		if m := taskItem.FindStringSubmatch(line); m != nil {
			current = -1
			if m[1] != " " {
				texts = append(texts, m[2])
				current = len(texts) - 1
			}
			continue
		}
		if strings.TrimSpace(line) == "" || listItem.MatchString(line) {
			current = -1
			continue
		}
		if current >= 0 {
			texts[current] += "\n" + line
		}
	}
	for _, text := range texts {
		b := classifyItem(text)
		items[b] = append(items[b], text)
	}
	return items
}

func classifyItem(text string) box {
	plain := strings.ToLower(strings.TrimSpace(strings.NewReplacer("*", "", "_", "", "`", "").Replace(text)))
	for _, p := range boxPrefixes {
		if strings.HasPrefix(plain, p.prefix) {
			return p.box
		}
	}
	return noBox
}

// countLinks counts distinct links to comments on this PR in text.
func countLinks(text string, pr pullRequest) int {
	seen := map[string]bool{}
	for _, m := range commentLink.FindAllStringSubmatch(text, -1) {
		n, err := strconv.Atoi(m[2])
		if err != nil || n != pr.number || !strings.EqualFold(m[1], pr.repo) {
			continue
		}
		seen[m[0]] = true
	}
	return len(seen)
}

// bodyProblems reports ticked loop boxes that lack links to their outputs.
func bodyProblems(pr pullRequest) []string {
	items := tickedItems(pr.body)
	loopNeeds, loopOutputs := 2, "tester verdict, auditor decision"
	if len(items[externalBox]) > 0 {
		loopNeeds, loopOutputs = 3, "tester verdict, security review, auditor decision"
	}
	var problems []string
	for _, text := range items[loopBox] {
		problems = append(problems, linkProblem("agent-loop", text, pr, loopNeeds, loopOutputs)...)
	}
	for _, text := range items[docsBox] {
		problems = append(problems, linkProblem("Documentation-only", text, pr, 1, "auditor decision")...)
	}
	return problems
}

func linkProblem(name, text string, pr pullRequest, needs int, outputs string) []string {
	got := countLinks(text, pr)
	if got >= needs {
		return nil
	}
	return []string{fmt.Sprintf("the ticked %s box links %d comment(s) on this PR; it needs %d (%s), each a link such as https://github.com/%s/pull/%d#issuecomment-<id>",
		name, got, needs, outputs, pr.repo, pr.number)}
}
