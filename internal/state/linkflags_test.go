package state

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// testingLinkFlag matches a linker -X that sets a variable of package
// testing, in any spelling the go command and goreleaser accept.
var testingLinkFlag = regexp.MustCompile(`-X(\s+|=)["']?testing\.`)

// Acceptance (#160, tester L4): -X testing.testBinary=1 would make
// testing.Testing report true in creep itself and re-enable OpenWithSecret.
// No build config this repository ships (the Makefile, goreleaser, the
// workflows) may set a testing variable at link time.
func TestBuildConfigsSetNoTestingSymbol(t *testing.T) {
	root := filepath.Join("..", "..")
	workflows, err := filepath.Glob(filepath.Join(root, ".github", "workflows", "*.y*ml"))
	if err != nil || len(workflows) == 0 {
		t.Fatalf("no workflows under %s: %v", root, err)
	}
	configs := append([]string{filepath.Join(root, "Makefile"), filepath.Join(root, ".goreleaser.yaml")}, workflows...)
	for _, name := range configs {
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if loc := testingLinkFlag.FindIndex(data); loc != nil {
			t.Errorf("%s sets a testing variable at link time: %q", name, data[loc[0]:loc[1]])
		}
	}
}

func TestTestingLinkFlagCatchesSpellings(t *testing.T) {
	tests := []struct {
		src  string
		want bool
	}{
		{`-ldflags "-X testing.testBinary=1"`, true},
		{`-X=testing.testBinary=1`, true},
		{"      - -X testing.testBinary=1", true},
		{`-X 'testing.testBinary=1'`, true},
		{`GOFLAGS=-ldflags=-X=testing.testBinary=1`, true},
		{`-X $(BUILDINFO).version=dev`, false},
		{`-X github.com/sneakercreepers/creep/internal/buildinfo.commit={{ .FullCommit }}`, false},
		{`-X example.com/testing.v=1`, false},
	}
	for _, tt := range tests {
		if got := testingLinkFlag.MatchString(tt.src); got != tt.want {
			t.Errorf("match %q = %v; want %v", tt.src, got, tt.want)
		}
	}
}
