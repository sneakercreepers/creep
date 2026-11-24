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

// adrProblems lists every Accepted ADR from 0019 on that names no fitness
// function (docs/adr/0000-template.md), so a decision cannot land without
// a check or an explicit "manual: auditor" (v0.4 architecture review A3,
// which recurred from the v0.3 review).
func adrProblems(root string) ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(root, "docs", "adr"))
	if err != nil {
		return nil, err
	}
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
		if missesFitness(data) {
			problems = append(problems, fmt.Sprintf("docs/adr/%s is Accepted but has no \"- **Fitness function:**\" header line", e.Name()))
		}
	}
	return problems, nil
}

// missesFitness reports whether an ADR's header says Accepted but has no
// Fitness function line.
func missesFitness(data []byte) bool {
	accepted, fitness := false, false
	sc := bufio.NewScanner(bytes.NewReader(data))
	for i := 0; i < adrHeaderLines && sc.Scan(); i++ {
		line := sc.Bytes()
		accepted = accepted || bytes.HasPrefix(line, []byte("- **Status:** Accepted"))
		fitness = fitness || bytes.HasPrefix(line, []byte("- **Fitness function:** "))
	}
	return accepted && !fitness
}

// v0.4 review A3: an Accepted ADR from 0019 on must name its fitness
// function; older, proposed and superseded ADRs and other files pass.
func TestADRFitnessCheck(t *testing.T) {
	const fitness = "- **Fitness function:** the row \"x\" of architecture.md §9\n"
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			writeFile(t, root, "docs/adr/"+tt.file, tt.content)
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
