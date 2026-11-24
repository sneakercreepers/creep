package main

import (
	"fmt"
	"io"
	"strings"
)

// checkedDocs are documentation files that make check, CI lint or a test
// reads, lowercase: a change to one can fail CI, so it never skips the
// heavy jobs (ADR 0018 amendment, 2026-11-23). A new test that reads a doc
// adds its path here; a push to main runs everything, so a miss shows there.
var checkedDocs = map[string]bool{
	"readme.md":            true, // discover's docs test
	"docs/architecture.md": true, // make budget layers table, make map
	"docs/map.md":          true, // make map-check
}

// checkedDocDirs are folders under docs/ that tests or CI lint read, lowercase.
var checkedDocDirs = []string{
	"docs/bench/",    // TestBenchPublished
	"docs/schemas/",  // report and recipe schema tests
	"docs/examples/", // actionlint in the workflows job
}

// ciSkippable reports whether CI may skip its heavy jobs for this path: it
// fits the docs-only shortcut (docsOnlyReason), sits at the root or under
// docs/, where no package embeds or reads it as test data, and no check
// reads it. Everything else, *.md in a package included, runs the full CI.
func ciSkippable(p string) bool {
	if docsOnlyReason(p) != "" {
		return false
	}
	lower := strings.ToLower(p)
	if !strings.HasPrefix(p, "docs/") && strings.Contains(p, "/") {
		return false
	}
	if checkedDocs[lower] {
		return false
	}
	for _, dir := range checkedDocDirs {
		if strings.HasPrefix(lower, dir) {
			return false
		}
	}
	return true
}

// docsOnlyScope is true only when there are changed files and CI may skip
// the heavy jobs for every one of them. An empty list runs everything.
func docsOnlyScope(files []string) bool {
	if len(files) == 0 {
		return false
	}
	for _, f := range files {
		if !ciSkippable(f) {
			return false
		}
	}
	return true
}

// runCIScope prints docs_only=true or docs_only=false for $GITHUB_OUTPUT.
// An unreadable list exits 2 and prints nothing, so the workflow output
// stays empty and every heavy job runs.
func runCIScope(files string, out, errOut io.Writer) int {
	if files == "" {
		fmt.Fprintln(errOut, "prcheck: -files is required with -ci-scope")
		return 2
	}
	list, err := readFiles(files)
	if err != nil {
		fmt.Fprintln(errOut, "prcheck:", err)
		return 2
	}
	fmt.Fprintf(out, "docs_only=%t\n", docsOnlyScope(list))
	return 0
}
