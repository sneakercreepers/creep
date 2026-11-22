package sandbox

import (
	"slices"
	"testing"
)

// TestSplitImageCheckedWhole (PR #307 review): BuildKit joins a continued
// line with nothing between the pieces, so an image name split over two
// lines is one name; the check returns it whole and the build cannot pull
// it unchecked.
func TestSplitImageCheckedWhole(t *testing.T) {
	for _, file := range []string{
		"FROM attacker.example/ev\\\nil\n",
		"FROM busybox\nCOPY --from=attacker.example/ev\\\nil /a /b\n",
		"FROM busybox\nRUN --mount=type=bind,from=attacker.example/ev\\\nil,target=/m true\n",
	} {
		images, _, rule := checkDockerfile([]byte(file))
		if rule != "" || !slices.Contains(images, "attacker.example/evil") {
			t.Errorf("%q: images %q, rule %q, want attacker.example/evil", file, images, rule)
		}
	}
}
