package sandbox

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// WriteSyntheticEnv writes a .env file that gives each name a fresh random
// placeholder and returns its path, to mount read-only into a container.
// An app under test reads it instead of the repository's or the host's
// .env, so no real secret is ever inside a container. Names follow the
// env-variable rule; duplicates collapse.
func (s *Sandbox) WriteSyntheticEnv(names []string) (string, error) {
	if len(names) > maxEnv {
		return "", fmt.Errorf("synthetic env: %d names: %w", len(names), ErrSpec)
	}
	sorted := slices.Clone(names)
	slices.Sort(sorted)
	sorted = slices.Compact(sorted)
	var b strings.Builder
	for _, name := range sorted {
		if !envName.MatchString(name) {
			return "", fmt.Errorf("synthetic env: name %q: %w", name, ErrSpec)
		}
		b.WriteString(name + "=creep-synthetic-" + rand.Text()[:16] + "\n")
	}
	dir := filepath.Join(s.work, "env-"+strconv.FormatUint(s.seq.Add(1), 10))
	if err := os.Mkdir(dir, 0o700); err != nil {
		return "", fmt.Errorf("synthetic env: %w", err)
	}
	path := filepath.Join(dir, ".env")
	// G306: the container user (65534) must read it; the work directory is
	// 0700, so no other host user can reach it, and it holds no secret.
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil { //nolint:gosec // G306, see above
		return "", fmt.Errorf("synthetic env: %w", err)
	}
	return path, nil
}
