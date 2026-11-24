package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sneakercreepers/creep/internal/redact"
)

// digestRepo writes files into a new directory and opens it as a root.
func digestRepo(t testing.TB, files map[string][]byte) *os.Root {
	t.Helper()
	dir := t.TempDir()
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	return root
}

func digester(root *os.Root, whole ...string) filesDigester {
	d := filesDigester{read: readRepoFile(root), stat: root.Lstat}
	if whole != nil {
		d.whole = map[string]bool{}
		for _, p := range whole {
			d.whole[p] = true
		}
	}
	return d
}

// Regression (v0.4 release pentest P1): the files digest stops when the
// run's context ends, an MCP call the agent called off or the scan
// deadline, before it reads another file, and says why.
func TestFilesDigestStops(t *testing.T) {
	root := digestRepo(t, map[string][]byte{"a.py": []byte("a\n"), "b.py": []byte("b\n")})
	files := repoFiles{paths: []string{"a.py", "b.py"}}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	expired, stop := context.WithTimeoutCause(context.Background(), -time.Second, errScanDeadline)
	defer stop()
	tests := []struct {
		name string
		ctx  context.Context
		want error
	}{
		{"running", context.Background(), nil},
		{"canceled", canceled, context.Canceled},
		{"deadline", expired, errScanDeadline},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			read := 0
			d := digester(root)
			inner := d.read
			d.read = func(p string) ([]byte, error) { read++; return inner(p) }
			_, err := d.digest(tt.ctx, files)
			if !errors.Is(err, tt.want) || (tt.want != nil && read != 0) {
				t.Fatalf("err = %v after %d reads; want %v", err, read, tt.want)
			}
		})
	}
}

// A --changed scan hashes only the listed files' content; the rest stand
// by size and modification time, so a pull-request scan does not read the
// whole tree (v0.4 release pentest P1).
func TestFilesDigestChangedScope(t *testing.T) {
	same := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name    string
		change  func(t *testing.T, root *os.Root)
		differs bool
	}{
		{"nothing", func(*testing.T, *os.Root) {}, false},
		{"listed file content", func(t *testing.T, r *os.Root) { writeIn(t, r, "listed.py", "LISTED\n", same) }, true},
		{"unlisted file size", func(t *testing.T, r *os.Root) { writeIn(t, r, "other.py", "other, longer\n", same) }, true},
		{"unlisted file time", func(t *testing.T, r *os.Root) { writeIn(t, r, "other.py", "other\n", same.Add(time.Hour)) }, true},
		{"unlisted content, same size and time", func(t *testing.T, r *os.Root) { writeIn(t, r, "other.py", "OTHER\n", same) }, false},
	}
	files := repoFiles{paths: []string{"listed.py", "other.py"}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := digestRepo(t, nil)
			writeIn(t, root, "listed.py", "listed\n", same)
			writeIn(t, root, "other.py", "other\n", same)
			before, err := digester(root, "listed.py").digest(context.Background(), files)
			if err != nil {
				t.Fatal(err)
			}
			tt.change(t, root)
			after, err := digester(root, "listed.py").digest(context.Background(), files)
			if err != nil || (before != after) != tt.differs {
				t.Fatalf("digest changed = %v (%v); want %v", before != after, err, tt.differs)
			}
		})
	}
}

func writeIn(t *testing.T, root *os.Root, name, data string, mtime time.Time) {
	t.Helper()
	if err := root.WriteFile(name, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := root.Chtimes(name, mtime, mtime); err != nil {
		t.Fatal(err)
	}
}

// BenchmarkFilesDigest backs filesDigester's documented worst case (v0.4
// review A4): every walked file at redact.MaxFileBytes, read whole and
// hashed, here 32 of them (32 MiB per digest).
func BenchmarkFilesDigest(b *testing.B) {
	files := map[string][]byte{}
	var paths []string
	for i := range 32 {
		name := fmt.Sprintf("f%02d.py", i)
		files[name] = bytes.Repeat([]byte("x = 1\n"), redact.MaxFileBytes/6)
		paths = append(paths, name)
	}
	root := digestRepo(b, files)
	d := digester(root)
	b.SetBytes(int64(32 * redact.MaxFileBytes))
	for b.Loop() {
		if _, err := d.digest(context.Background(), repoFiles{paths: paths}); err != nil {
			b.Fatal(err)
		}
	}
}
