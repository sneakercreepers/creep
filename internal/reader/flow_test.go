package reader

import (
	"reflect"
	"strings"
	"testing"
)

func TestAssignment(t *testing.T) {
	tests := []struct {
		line, lhs, rhs string
		ok             bool
	}{
		{"    q = a + b", "q ", " a + b", true},
		{"q += a", "q +", " a", true},
		{"x, y = f(z)", "x, y ", " f(z)", true},
		{"d[k] = v", "d[k] ", " v", true},
		{"n := g(a)", "n :", " g(a)", true},
		{"for row in rows:", "row", "rows:", true},
		{"with open(p) as fh:", "fh:", "with open(p)", true},
		{"if a == b:", "", "", false},
		{"if a != b and c <= d or e >= f:", "", "", false},
		{"f(a=1, b=2)", "", "", false},
		{"return x", "", "", false},
		{"", "", "", false},
	}
	for _, tt := range tests {
		lhs, rhs, ok := assignment(tt.line)
		if lhs != tt.lhs || rhs != tt.rhs || ok != tt.ok {
			t.Errorf("assignment(%q) = %q, %q, %v; want %q, %q, %v", tt.line, lhs, rhs, ok, tt.lhs, tt.rhs, tt.ok)
		}
	}
}

func TestSlicePicks(t *testing.T) {
	tests := []struct {
		name         string
		src          string
		source, sink int
		want         []int
		partial      bool
	}{
		{"transitive assignments", "def h(a):\n    b = a\n    c = 1\n    d = b + c\n    run(d)\n", 1, 5, []int{5, 1, 4, 3, 2}, false},
		{"unrelated lines left out", "def h(a):\n    b = a\n    z = 9\n    run(b)\n", 1, 4, []int{4, 1, 2}, false},
		{"for and with targets", "def h(a):\n    for x in a:\n        with open(x) as fh:\n            run(fh)\n", 1, 4, []int{4, 1, 3, 2}, false},
		{"guard and its body", "def h(a):\n    if bad(a):\n        abort(400)\n    run(a)\n", 1, 4, []int{4, 1, 3, 2}, false},
		{"multi-line def and decorators", "@r(\"/\")\n@auth\ndef h(a,\n      b):\n    run(b)\n", 3, 5, []int{5, 3, 4, 2, 1}, false},
		{"sink in a helper", "def helper(x):\n    y = x\n    run(y)\n\n@r(\"/\")\ndef h(a):\n    helper(a)\n", 6, 3, []int{3, 6, 5, 1, 2}, false},
		{"walk stops at the enclosing def", "x = 1\ndef h(a):\n    run(x)\n", 2, 3, []int{3, 2}, false},
		{"module-level sink", "x = input()\nrun(x)\n", 1, 2, []int{2, 1, 1}, false},
		{"long function is cut", "def h(a):\n" + strings.Repeat("    pad = 0\n", maxScanBytes/12+1) + "    run(a)\n", 1, maxScanBytes/12 + 3, []int{maxScanBytes/12 + 3, 1}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := slicePicks(splitLines(tt.src), tt.source, tt.sink)
			if !reflect.DeepEqual(got.lines, tt.want) || got.partial != tt.partial {
				t.Fatalf("slicePicks = %v, partial %v; want %v, %v", got.lines, got.partial, tt.want, tt.partial)
			}
		})
	}
}

// Hostile decorator runs and unterminated defs cannot grow the header past
// maxHeaderLines.
func TestHeaderIsCapped(t *testing.T) {
	src := strings.Repeat("@d\n", 50) + "def h(a,\n" + strings.Repeat("  a,\n", 50) + "):\n    run(a)\n"
	lines := splitLines(src)
	if n := len(decorators(lines, 51)); n != maxHeaderLines {
		t.Errorf("decorators = %d lines, want %d", n, maxHeaderLines)
	}
	if n := len(defContinuation(lines, 51)); n != maxHeaderLines {
		t.Errorf("defContinuation = %d lines, want %d", n, maxHeaderLines)
	}
}
