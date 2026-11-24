package main

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The ADR fitness check lives only in tests (go test ./... in CI and make
// check): §6 caps this package's source lines, and the check needs nothing
// at run time.

// firstFitnessADR is the first ADR written after the template gained its
// Fitness function line; older ADRs predate it.
const firstFitnessADR = 19

// adrHeaderLines bounds how far into an ADR its header lines are read.
const adrHeaderLines = 15

var adrName = regexp.MustCompile(`^(\d{4})-[a-z0-9-]+\.md$`)

// adrProblems lists every Accepted ADR from 0019 on whose Fitness function
// header line is missing or names, in quotes, no row of architecture.md §9
// (docs/adr/0000-template.md), so a decision cannot land without a real
// check or an explicit "manual: auditor" (v0.4 architecture review A3,
// which recurred from the v0.3 review; tester T6).
func adrProblems(root string) ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(root, "docs", "adr"))
	if err != nil {
		return nil, err
	}
	arch, err := readPolicyFile(root, "docs/architecture.md")
	if err != nil {
		return nil, err
	}
	rows := fitnessRows(arch)
	var problems []string
	for _, e := range entries {
		m := adrName.FindStringSubmatch(e.Name())
		if m == nil || !e.Type().IsRegular() {
			continue
		}
		if n, _ := strconv.Atoi(m[1]); n < firstFitnessADR {
			continue
		}
		data, err := readPolicyFile(root, "docs/adr/"+e.Name())
		if err != nil {
			return nil, err
		}
		if why := fitnessProblem(data, rows); why != "" {
			problems = append(problems, fmt.Sprintf("docs/adr/%s: %s", e.Name(), why))
		}
	}
	return problems, nil
}

// fitnessProblem says why an Accepted ADR's header does not name a real
// fitness function, or "" when it does or is not Accepted.
func fitnessProblem(data []byte, rows []string) string {
	accepted, line := false, ""
	sc := bufio.NewScanner(bytes.NewReader(data))
	for i := 0; i < adrHeaderLines && sc.Scan(); i++ {
		accepted = accepted || strings.HasPrefix(sc.Text(), "- **Status:** Accepted")
		if v, ok := strings.CutPrefix(sc.Text(), "- **Fitness function:** "); ok {
			line = v
		}
	}
	switch {
	case !accepted || strings.HasPrefix(line, "manual: auditor"):
		return ""
	case line == "":
		return "Accepted but has no \"- **Fitness function:**\" header line"
	}
	names := quoted.FindAllStringSubmatch(line, -1)
	if len(names) == 0 {
		return "the Fitness function line names no §9 row in quotes"
	}
	for _, n := range names {
		if !hasRow(rows, n[1]) {
			return fmt.Sprintf("the Fitness function line names %q, which is no row of architecture.md §9", n[1])
		}
	}
	return ""
}

var quoted = regexp.MustCompile(`"([^"]+)"`)

// fitnessRows are the Property cells of architecture.md §9's table.
func fitnessRows(arch []byte) []string {
	text := string(arch)
	start := strings.Index(text, "## 9. Fitness functions")
	if start < 0 {
		return nil
	}
	text = text[start:]
	if end := strings.Index(text[1:], "\n## "); end >= 0 {
		text = text[:end+1]
	}
	var rows []string
	for _, line := range strings.Split(text, "\n") {
		cells := strings.Split(line, " | ")
		if strings.HasPrefix(line, "| ") && len(cells) > 1 {
			rows = append(rows, strings.TrimPrefix(cells[0], "| "))
		}
	}
	return rows
}

// hasRow reports whether a §9 Property cell starts with name; a cell may
// add its issue or ADR in parentheses.
func hasRow(rows []string, name string) bool {
	for _, r := range rows {
		if strings.HasPrefix(r, name) {
			return true
		}
	}
	return false
}

// v0.4 review A3: an Accepted ADR from 0019 on must name its fitness
// function; older, proposed and superseded ADRs and other files pass.
func TestADRFitnessCheck(t *testing.T) {
	const fitness = "- **Fitness function:** the row \"Real row\" of architecture.md §9\n"
	tests := []struct {
		name, file, content string
		problem             bool
	}{
		{"accepted with fitness", "0031-init.md", "# ADR\n\n- **Status:** Accepted (maintainer)\n" + fitness, false},
		{"accepted without fitness", "0032-resume.md", "# ADR\n\n- **Status:** Accepted (maintainer)\n- **Date:** 2026-11-24\n", true},
		{"fitness only in the body", "0033-x.md", "# ADR\n\n- **Status:** Accepted\n" + strings.Repeat("\n", adrHeaderLines) + fitness, true},
		{"proposed", "0033-x.md", "# ADR\n\n- **Status:** Proposed\n", false},
		{"superseded", "0033-x.md", "# ADR\n\n- **Status:** Superseded by ADR-0040\n", false},
		{"before the template line", "0018-old.md", "# ADR\n\n- **Status:** Accepted\n", false},
		{"not an ADR file", "dependencies.txt", "- **Status:** Accepted\n", false},
		{"names no real row", "0033-x.md", "- **Status:** Accepted\n- **Fitness function:** the row \"Imagined row\" of §9\n", true},
		{"one of two rows is not real", "0033-x.md", "- **Status:** Accepted\n- **Fitness function:** the rows \"Real row\" and \"Imagined row\"\n", true},
		{"names no row at all", "0033-x.md", "- **Status:** Accepted\n- **Fitness function:** see §9\n", true},
		{"manual", "0033-x.md", "- **Status:** Accepted\n- **Fitness function:** manual: auditor\n", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			writeFile(t, root, "docs/adr/"+tt.file, tt.content)
			writeFile(t, root, "docs/architecture.md", "## 9. Fitness functions\n\n| Property | Check |\n|---|---|\n| Real row (ADR 0033) | `TestX` |\n\n## 10. Next\n| Imagined row | no |\n")
			problems, err := adrProblems(root)
			if err != nil || (len(problems) > 0) != tt.problem {
				t.Fatalf("problems %v, err %v; want a problem: %v", problems, err, tt.problem)
			}
		})
	}
}

// TestADRsNameFitnessFunction is the check on the repository's own ADRs
// (architecture.md §9, "Every accepted decision names its fitness
// function").
func TestADRsNameFitnessFunction(t *testing.T) {
	problems, err := adrProblems(filepath.Join("..", "..", ".."))
	if err != nil || len(problems) > 0 {
		t.Fatalf("problems %v, err %v", problems, err)
	}
}
