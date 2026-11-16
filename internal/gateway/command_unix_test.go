//go:build unix

package gateway

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Security (#6 review L1, I1): a symlink outside the repository that leads
// to a program inside it is refused, and the error names the link.
func TestNewCommandRefusesLinkIntoRepo(t *testing.T) {
	repo, outside := t.TempDir(), t.TempDir()
	bin := filepath.Join(repo, "cli")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o700); err != nil { //nolint:gosec // G306: LookPath needs an executable file
		t.Fatal(err)
	}
	link := filepath.Join(outside, "cli")
	if err := os.Symlink(bin, link); err != nil {
		t.Fatal(err)
	}
	opts := fakeOptions(t, "echo", time.Second)
	opts.Run, opts.RepoDir = "'"+link+"'", repo
	_, err := NewCommand(opts)
	if !errors.Is(err, ErrCommand) || !strings.Contains(err.Error(), "follows a link or junction") {
		t.Fatalf("NewCommand = %v, want a link refusal", err)
	}
}
