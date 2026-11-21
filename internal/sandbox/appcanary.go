package sandbox

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
)

// AppCanaryFile is where StartApp plants the app's canary file: a path a
// traversal PoC reaches from any directory, with content no image, model
// or repository can know.
const AppCanaryFile = "/etc/creep-canary"

// plantCanary writes a file of fresh random content in the work directory
// and returns its mount at AppCanaryFile.
func (s *Sandbox) plantCanary() (Mount, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return Mount{}, fmt.Errorf("app canary: %w", err)
	}
	content := "creep-canary-" + hex.EncodeToString(b[:])
	dir := filepath.Join(s.work, "app-canary")
	if err := os.Mkdir(dir, 0o700); err != nil {
		return Mount{}, fmt.Errorf("app canary: %w", err)
	}
	path := filepath.Join(dir, "creep-canary")
	// G306: the app's user must read it; the work directory is 0700.
	if err := os.WriteFile(path, []byte(content+"\n"), 0o644); err != nil { //nolint:gosec // G306, see above
		return Mount{}, fmt.Errorf("app canary: %w", err)
	}
	s.mu.Lock()
	s.fileCanary = content
	s.mu.Unlock()
	return Mount{Source: path, Target: AppCanaryFile}, nil
}

// AppCanary is the content of the canary file StartApp planted in the
// app's container, or "" before it. Only a read of that file in the app
// can put it in a response.
func (s *Sandbox) AppCanary() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.fileCanary
}
