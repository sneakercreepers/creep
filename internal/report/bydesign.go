package report

import (
	"fmt"
	"strings"
)

// byDesignOrder fixes the order reasons are counted in, so every format
// prints the same summary for the same files.
var byDesignOrder = []SkipReason{SkipVendor, SkipGenerated, SkipMinified}

// ByDesign reports whether a file listed with reason r was left out on
// purpose (ADR 0009): it stays listed, but it is not a gap that makes the
// run incomplete. Every other reason is a gap.
func (r SkipReason) ByDesign() bool {
	switch r {
	case SkipVendor, SkipGenerated, SkipMinified:
		return true
	}
	return false
}

// ByDesignSummary counts the files left out by design, such as "3 files
// left out by design (vendor 2, generated 1)", or returns "" when there is
// none. Every format prints it beside the class coverage, so a covered
// class never reads as covering those files (#213). It holds only counts
// and reason IDs, never a path.
func ByDesignSummary(files []NotEvaluated) string {
	counts := map[SkipReason]int{}
	total := 0
	for _, f := range files {
		if f.Reason.ByDesign() {
			counts[f.Reason]++
			total++
		}
	}
	if total == 0 {
		return ""
	}
	parts := make([]string, 0, len(byDesignOrder))
	for _, r := range byDesignOrder {
		if counts[r] > 0 {
			parts = append(parts, fmt.Sprintf("%s %d", r, counts[r]))
		}
	}
	noun := "files"
	if total == 1 {
		noun = "file"
	}
	return fmt.Sprintf("%d %s left out by design (%s)", total, noun, strings.Join(parts, ", "))
}
