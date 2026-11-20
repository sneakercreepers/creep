package main

import "testing"

// docsLine is the template's Documentation-only box, ticked.
const docsLine = "- [x] Documentation-only (`*.md` or `docs/`): ran only the auditor."

func TestDocsOnlyClaimed(t *testing.T) {
	tests := []struct {
		name string
		body string
		want bool
	}{
		{"template box ticked", docsLine, true},
		{"capital X", "- [X] Documentation-only", true},
		{"other bullets", "* [x] Documentation-only\n", true},
		{"ordered list", "1. [x] Documentation-only", true},
		{"emphasis and case", "- [x] **documentation-ONLY**: yes", true},
		{"indented", "    - [x] Documentation-only", true},
		{"blockquote", "> - [x] Documentation-only", true},
		{"CRLF", "intro\r\n" + docsLine + "\r\n", true},
		{"after a code span that opens a comment", "Strip from `<!--` on.\n" + docsLine, true},
		{"inside a comment still counts", "<!--\n" + docsLine + "\n-->", true},
		{"space instead of hyphen", "- [x] Documentation only", true},
		{"no separator", "- [x] DocumentationOnly", true},
		{"link", "- [x] [Documentation-only](https://example.com/docs): yes", true},
		{"autolink before", "- [x] <https://example.com> Documentation-only", true},
		{"HTML tags", "- [x] <b>Documentation</b>-<i>only</i>", true},
		{"numeric entity", "- [x] Documentation&#45;only", true},
		{"named entities", "- [x] &lt;b&gt;Documentation&nbsp;only", true},
		{"unticked", "- [ ] Documentation-only", false},
		{"other words", "- [x] Documentation updated", false},
		{"other box ticked", "- [x] AI-assisted: ran the agent loop", false},
		{"not a task item", "Documentation-only [x]", false},
		{"mentioned in prose", "This is not Documentation-only.", false},
		{"empty", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := docsOnlyClaimed(tt.body); got != tt.want {
				t.Fatalf("docsOnlyClaimed(%q) = %v, want %v", tt.body, got, tt.want)
			}
		})
	}
}
