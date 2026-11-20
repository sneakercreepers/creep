package main

import (
	"strings"
	"testing"
)

const (
	repo     = "sneakercreepers/creep"
	tester   = "https://github.com/sneakercreepers/creep/pull/7#issuecomment-11"
	auditor  = "https://github.com/sneakercreepers/creep/pull/7#issuecomment-22"
	security = "https://github.com/sneakercreepers/creep/pull/7#pullrequestreview-33"
)

// The template's AI-assistance lines, as a contributor fills them in.
const (
	loopLine     = "- [x] AI-assisted: ran the agent loop developer → tester → pentester → auditor. Tester verdict, security review and auditor decision: "
	externalLine = "- [x] External contributor: the pentester ran with no shared context."
	docsLine     = "- [x] Documentation-only (`*.md` or `docs/`): ran only the auditor. Auditor decision: "
)

func TestBodyProblems(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string // substring of the problems; "" means none
	}{
		{"no box ticked", "- [ ] AI-assisted: ran the agent loop\n- [ ] Documentation-only", ""},
		{"empty body", "", ""},
		{"declaration box only", "- [x] AI-assisted (tool/model: Claude). I reviewed every line.", ""},
		{"loop with both links", loopLine + tester + " " + auditor, ""},
		{"loop with markdown links", loopLine + "[tester](" + tester + "), [auditor](" + auditor + ")", ""},
		{"loop links on a continuation line", loopLine + "\n  " + tester + "\n  " + auditor, ""},
		{"loop with the placeholder", loopLine + "<!-- links -->", "links 0 comment(s)"},
		{"loop with pending", loopLine + "pending", "links 0 comment(s)"},
		{"loop with one link", loopLine + tester, "links 1 comment(s) on this PR; it needs 2"},
		{"loop with one link twice", loopLine + tester + " " + tester, "links 1 comment(s)"},
		{"loop links inside a comment", loopLine + "<!-- " + tester + " " + auditor + " -->", "links 0 comment(s)"},
		{"loop links after an unclosed comment", loopLine + "<!-- \n" + tester + " " + auditor, "links 0 comment(s)"},
		{"loop links to another PR", loopLine + strings.ReplaceAll(tester+" "+auditor, "/pull/7#", "/pull/8#"), "links 0 comment(s)"},
		{"loop links to another repo", loopLine + strings.ReplaceAll(tester+" "+auditor, "creep/pull", "other/pull"), "links 0 comment(s)"},
		{"loop links to the PR, not a comment", loopLine + "https://github.com/sneakercreepers/creep/pull/7 https://github.com/sneakercreepers/creep/pull/7/files", "links 0 comment(s)"},
		{"loop links after a blank line", loopLine + "\n\n" + tester + " " + auditor, "links 0 comment(s)"},
		{"loop links in the next item", loopLine + "\n- " + tester + " " + auditor, "links 0 comment(s)"},
		{"free-form loop box", "- [X] **AI-assisted:** agent loop developer → tester → auditor.", "agent-loop box links 0"},
		{"loop box with another bullet", "* [x] AI-assisted: loop", "agent-loop box links 0"},
		{"external needs the security review", loopLine + tester + " " + auditor + "\n" + externalLine, "it needs 3"},
		{"external with all three", loopLine + tester + " " + security + " " + auditor + "\n" + externalLine, ""},
		{"docs-only with the auditor link", docsLine + auditor, ""},
		{"docs-only with the placeholder", docsLine + "<!-- link -->", "Documentation-only box links 0"},
		{"docs-only with CRLF and no link", strings.ReplaceAll(docsLine+"\npending", "\n", "\r\n"), "Documentation-only box links 0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := strings.Join(bodyProblems(pullRequest{repo: repo, number: 7, body: tt.body}), "\n")
			if tt.want == "" && got != "" {
				t.Fatalf("unexpected problems: %s", got)
			}
			if !strings.Contains(got, tt.want) {
				t.Fatalf("problems %q do not contain %q", got, tt.want)
			}
		})
	}
}

func TestRepoMatchIgnoresCase(t *testing.T) {
	pr := pullRequest{repo: "SneakerCreepers/Creep", number: 7, body: loopLine + tester + " " + auditor}
	if p := bodyProblems(pr); len(p) > 0 {
		t.Fatalf("problems %v", p)
	}
}
