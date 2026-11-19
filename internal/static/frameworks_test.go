package static

import (
	"strings"
	"testing"
)

// FrameworkNames is what a scan with no route prints (#207): it must name
// every framework static extracts, so a framework added to the enum without
// moving lastFramework fails here instead of going unnamed.
func TestFrameworkNamesCoverEveryFramework(t *testing.T) {
	names := FrameworkNames()
	if len(names) != int(lastFramework) {
		t.Fatalf("FrameworkNames() = %v, want %d names", names, lastFramework)
	}
	for i, name := range names {
		f := Framework(i + 1)
		if name == "unknown" || !strings.EqualFold(name, f.String()) {
			t.Errorf("name %d = %q, want a title for %q", i, name, f)
		}
	}
	if next := lastFramework + 1; next.String() != "unknown" || next.title() != "unknown" {
		t.Errorf("framework %d is named %q: move lastFramework", next, next.String())
	}
}
