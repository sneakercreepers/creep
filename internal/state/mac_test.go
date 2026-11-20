package state

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// verify accepts only the lowercase hex sign writes, so a line has exactly
// one valid encoding and an edited MAC never verifies.
func TestVerifyRefusesNonCanonicalMAC(t *testing.T) {
	line, err := sign(testMAC, cacheDomain, []byte(`{"v":1}`))
	if err != nil {
		t.Fatal(err)
	}
	mac := string(line[len(line)-macLen+len(macField) : len(line)-2])
	letter := strings.IndexAny(mac, "abcdef")
	if letter < 0 {
		t.Fatalf("fixed MAC %s has no hex letter to change case", mac)
	}
	tests := []struct {
		name string
		mac  string
		ok   bool
	}{
		{"lowercase, as sign writes", mac, true},
		{"uppercase", strings.ToUpper(mac), false},
		{"one uppercase letter", mac[:letter] + strings.ToUpper(mac[letter:letter+1]) + mac[letter+1:], false},
	}
	for _, tt := range tests {
		edited := strings.Replace(string(line), mac, tt.mac, 1)
		_, err := verify(testMAC, cacheDomain, []byte(edited))
		if tt.ok && err != nil {
			t.Errorf("%s: verify = %v; want ok", tt.name, err)
		}
		if !tt.ok && !errors.Is(err, ErrUnauthenticated) {
			t.Errorf("%s: verify = %v; want ErrUnauthenticated", tt.name, err)
		}
	}
}

// Many first uses at once on an empty config dir agree on one key, and no
// temporary file is left behind.
func TestConcurrentFirstUseSharesOneKey(t *testing.T) {
	const rounds, users = 4, 16
	for range rounds {
		keyFile := isolateUserConfig(t)
		keys := firstUseAtOnce(t, users)
		for i, k := range keys {
			if !bytes.Equal(k, keys[0]) {
				t.Fatalf("user %d got a different key", i)
			}
		}
		checkNoTempFiles(t, filepath.Dir(keyFile))
	}
}

// firstUseAtOnce calls userSecret from n goroutines released together.
func firstUseAtOnce(t *testing.T, n int) [][]byte {
	t.Helper()
	keys := make([][]byte, n)
	errs := make([]error, n)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			<-start
			keys[i], errs[i] = userSecret()
		})
	}
	close(start)
	wg.Wait()
	if err := errors.Join(errs...); err != nil {
		t.Fatalf("concurrent first use: %v", err)
	}
	return keys
}

func checkNoTempFiles(t *testing.T, dir string) {
	t.Helper()
	tmp, err := filepath.Glob(filepath.Join(dir, ".tmp-*"))
	if err != nil || len(tmp) != 0 {
		t.Fatalf("temporary files left: %v, %v", tmp, err)
	}
}

// A creator that loses the race fails with ErrExist and never replaces the
// key another creator already wrote.
func TestCreateSecretKeepsExistingKey(t *testing.T) {
	keyFile := isolateUserConfig(t)
	first, err := userSecret()
	if err != nil {
		t.Fatal(err)
	}
	s, err := openDir(filepath.Dir(keyFile))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.createSecret("state.key"); !errors.Is(err, os.ErrExist) {
		t.Fatalf("createSecret over an existing key = %v; want ErrExist", err)
	}
	if again, err := userSecret(); err != nil || !bytes.Equal(again, first) {
		t.Fatalf("key changed after a lost race: %v", err)
	}
	checkNoTempFiles(t, filepath.Dir(keyFile))
}

// readSecret itself refuses a key file of the wrong length, even when it is
// valid hex of random-looking bytes.
func TestReadSecretRefusesWrongLength(t *testing.T) {
	tests := []struct {
		name string
		size int
		want error
	}{
		{"one byte short", SecretBytes - 1, ErrCorrupt},
		{"one byte long", SecretBytes + 1, ErrCorrupt},
		{"exact", SecretBytes, nil},
	}
	for _, tt := range tests {
		dir := t.TempDir()
		secret := make([]byte, tt.size)
		for i := range secret {
			secret[i] = byte(i) // distinct bytes: never a fixed pattern
		}
		if err := os.WriteFile(filepath.Join(dir, "state.key"), []byte(hex.EncodeToString(secret)), fileMode); err != nil {
			t.Fatal(err)
		}
		s, err := openDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		_, err = s.readSecret("state.key")
		_ = s.Close()
		if !errors.Is(err, tt.want) {
			t.Errorf("%s: readSecret = %v; want %v", tt.name, err, tt.want)
		}
	}
}
