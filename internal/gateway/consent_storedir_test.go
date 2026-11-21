package gateway

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// modeInfo is a FileInfo with only a mode, so the directory type check is
// tested on every OS, also for kinds a test cannot make everywhere (a
// junction on Unix, a symbolic link without privilege on Windows).
type modeInfo fs.FileMode

func (m modeInfo) Name() string       { return "creep" }
func (m modeInfo) Size() int64        { return 0 }
func (m modeInfo) Mode() fs.FileMode  { return fs.FileMode(m) }
func (m modeInfo) ModTime() time.Time { return time.Time{} }
func (m modeInfo) IsDir() bool        { return fs.FileMode(m).IsDir() }
func (m modeInfo) Sys() any           { return nil }

// The store directory must be a plain directory, refused by its own check
// (errNotPlainDir) before the access check, which on Windows checks
// nothing: removing the type check fails this test on every OS (#116).
func TestStoreDirMustBePlain(t *testing.T) {
	tests := []struct {
		name string
		mode fs.FileMode
	}{
		{"symbolic link", fs.ModeSymlink | 0o700},
		{"junction", fs.ModeDir | fs.ModeIrregular | 0o700},
		{"regular file", 0o700},
		{"device", fs.ModeDevice | 0o700},
		{"named pipe", fs.ModeNamedPipe | 0o700},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkStoreDir("creep", modeInfo(tt.mode))
			if !errors.Is(err, errNotPlainDir) || !errors.Is(err, ErrUnsafeConsentStore) {
				t.Fatalf("checkStoreDir(%v) = %v; want errNotPlainDir and ErrUnsafeConsentStore", tt.mode, err)
			}
		})
	}
	dir := t.TempDir()
	info, err := os.Lstat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkStoreDir(dir, info); err != nil {
		t.Fatalf("checkStoreDir(private directory) = %v; want nil", err)
	}
}

// A relative store path would resolve in the working directory, the
// scanned repository, so NewConsent refuses it.
func TestRelativeStorePathRefused(t *testing.T) {
	for _, p := range []string{"consent.json", filepath.Join(".creep", "consent.json"), filepath.Join("..", "consent.json")} {
		if _, err := NewConsent(ConsentOptions{StorePath: p}); !errors.Is(err, ErrUnsafeConsentStore) {
			t.Errorf("NewConsent(StorePath %q) = %v; want ErrUnsafeConsentStore", p, err)
		}
	}
}

// Reading checks the directory too: a valid store that grants the endpoint
// is refused when its directory is a link, before the prompt runs, and a
// missing directory is an empty store.
func TestStoreDirCheckedOnRead(t *testing.T) {
	target := t.TempDir()
	writeStore(t, filepath.Join(target, "consent.json"), storedA)
	link := filepath.Join(t.TempDir(), "creep")
	symlink(t, target, link)
	p := &countingPrompt{yes: true}
	c := newConsent(t, ConsentOptions{StorePath: filepath.Join(link, "consent.json"), Prompt: p.prompt})
	checkStoreRefusal(t, c.check(mustURL(t, "https://a.example/")), true)
	if !errors.Is(c.check(mustURL(t, "https://a.example/")), errNotPlainDir) || len(p.asked) != 0 {
		t.Fatalf("asked %v; want the link refused before any prompt", p.asked)
	}
	keys, err := readConsentStore(filepath.Join(t.TempDir(), "missing", "consent.json"))
	if err != nil || len(keys) != 0 {
		t.Fatalf("missing directory = %v, %v; want an empty store", keys, err)
	}
}
