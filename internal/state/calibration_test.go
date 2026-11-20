package state

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	calKeyA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	calKeyB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

var calAt = time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)

func calPath(s *Store, key string) string {
	return filepath.Join(s.dir, calibrationsDir, key+".json")
}

func saveCal(t *testing.T, s *Store, key string) {
	t.Helper()
	if err := s.SaveCalibration(key, Calibration{At: calAt, Result: json.RawMessage(`{"tier": "M"}`)}); err != nil {
		t.Fatal(err)
	}
}

func TestCalibrationRoundTrip(t *testing.T) {
	s := openStore(t)
	if _, ok, err := s.LoadCalibration(calKeyA); ok || err != nil {
		t.Fatalf("empty store: ok=%v err=%v; want a plain miss", ok, err)
	}
	local := time.FixedZone("x", 3600)
	if err := s.SaveCalibration(calKeyA, Calibration{At: calAt.In(local), Result: json.RawMessage("{\n\"tier\": \"M\"}")}); err != nil {
		t.Fatal(err)
	}
	c, ok, err := s.LoadCalibration(calKeyA)
	if !ok || err != nil || !c.At.Equal(calAt) || c.At.Location() != time.UTC || string(c.Result) != `{"tier":"M"}` {
		t.Fatalf("load = %+v, %v, %v; want the compacted result at %v UTC", c, ok, err, calAt)
	}
	data, _ := os.ReadFile(calPath(s, calKeyA))
	if bytes.Count(data, []byte("\n")) != 1 {
		t.Fatalf("file is not one line: %q", data)
	}
}

// Every damaged, planted or misplaced file is refused; a newer version is
// distinguished so the caller can fail closed instead of overwriting it.
func TestLoadCalibrationRefuses(t *testing.T) {
	tests := []struct {
		name    string
		damage  func(t *testing.T, s *Store, data []byte)
		want    error
		wantNot error
	}{
		{"torn", func(t *testing.T, s *Store, data []byte) {
			writeFile(t, calPath(s, calKeyA), data[:len(data)/2])
		}, ErrCorrupt, nil},
		{"two lines", func(t *testing.T, s *Store, data []byte) {
			writeFile(t, calPath(s, calKeyA), append(bytes.Clone(data), data...))
		}, ErrCorrupt, nil},
		{"unsigned", func(t *testing.T, s *Store, _ []byte) {
			writeFile(t, calPath(s, calKeyA), []byte(`{"v":1,"key":"`+calKeyA+`","at":"2026-11-14T12:00:00Z","result":{}}`+"\n"))
		}, ErrUnauthenticated, nil},
		{"planted by another secret", func(t *testing.T, s *Store, _ []byte) {
			saveCal(t, plantedStore(t, s.dir), calKeyA)
		}, ErrUnauthenticated, nil},
		{"copied from another key", func(t *testing.T, s *Store, _ []byte) {
			saveCal(t, s, calKeyB)
			b, _ := os.ReadFile(calPath(s, calKeyB))
			writeFile(t, calPath(s, calKeyA), b)
		}, ErrCorrupt, ErrUnauthenticated},
		{"run line domain", func(t *testing.T, s *Store, _ []byte) {
			line := `{"v":1,"key":"` + calKeyA + `","at":"2026-11-14T12:00:00Z","result":{}}`
			writeFile(t, calPath(s, calKeyA), signedLog(fixtureRunID, line+"\n"))
		}, ErrUnauthenticated, nil},
		{"newer version", func(t *testing.T, s *Store, _ []byte) {
			line := `{"v":2,"key":"` + calKeyA + `","at":"2026-11-14T12:00:00Z","result":{}}`
			writeFile(t, calPath(s, calKeyA), signLines(line+"\n", calibrationDomain))
		}, ErrUnsupportedVersion, ErrCorrupt},
		{"result not an object", func(t *testing.T, s *Store, _ []byte) {
			line := `{"v":1,"key":"` + calKeyA + `","at":"2026-11-14T12:00:00Z","result":[1]}`
			writeFile(t, calPath(s, calKeyA), signLines(line+"\n", calibrationDomain))
		}, ErrCorrupt, nil},
		{"no time", func(t *testing.T, s *Store, _ []byte) {
			line := `{"v":1,"key":"` + calKeyA + `","result":{}}`
			writeFile(t, calPath(s, calKeyA), signLines(line+"\n", calibrationDomain))
		}, ErrCorrupt, nil},
		{"oversized", func(t *testing.T, s *Store, _ []byte) {
			writeFile(t, calPath(s, calKeyA), bytes.Repeat([]byte("x"), MaxCalibrationBytes+1))
		}, ErrCorrupt, nil},
		{"directory", func(t *testing.T, s *Store, _ []byte) {
			_ = os.Remove(calPath(s, calKeyA))
			if err := os.Mkdir(calPath(s, calKeyA), dirMode); err != nil {
				t.Fatal(err)
			}
		}, ErrUnsafePath, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := openStore(t)
			saveCal(t, s, calKeyA)
			data, _ := os.ReadFile(calPath(s, calKeyA))
			tt.damage(t, s, data)
			_, ok, err := s.LoadCalibration(calKeyA)
			if ok || !errors.Is(err, tt.want) || (tt.wantNot != nil && errors.Is(err, tt.wantNot)) {
				t.Fatalf("ok=%v err=%v; want %v and not %v", ok, err, tt.want, tt.wantNot)
			}
		})
	}
}

func TestCalibrationLinkRefused(t *testing.T) {
	s := openStore(t)
	saveCal(t, s, calKeyB)
	if err := os.Symlink(calPath(s, calKeyB), calPath(s, calKeyA)); err != nil {
		t.Skipf("symlink: %v", err)
	}
	if _, ok, err := s.LoadCalibration(calKeyA); ok || !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("load via link: ok=%v err=%v; want ErrUnsafePath", ok, err)
	}
}

// A calibrations/ directory that is a link or a file is a hard error on
// load and on save, never followed, and the error names the absolute path
// to remove (#180): recalibrating cannot replace it.
func TestUnsafeCalibrationDirNamesPath(t *testing.T) {
	tests := []struct {
		name  string
		plant func(t *testing.T, dir string)
	}{
		{"link to a directory outside", func(t *testing.T, dir string) {
			if err := os.Symlink(t.TempDir(), dir); err != nil {
				t.Skipf("symlink: %v", err)
			}
		}},
		{"link to a directory inside", func(t *testing.T, dir string) {
			inside := filepath.Join(filepath.Dir(dir), "elsewhere")
			if err := os.Mkdir(inside, dirMode); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(inside, dir); err != nil {
				t.Skipf("symlink: %v", err)
			}
		}},
		{"a file", func(t *testing.T, dir string) { writeFile(t, dir, []byte("not a directory")) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := openStore(t)
			dir := filepath.Join(s.dir, calibrationsDir)
			tt.plant(t, dir)
			_, ok, loadErr := s.LoadCalibration(calKeyA)
			saveErr := s.SaveCalibration(calKeyA, Calibration{At: calAt, Result: json.RawMessage(`{}`)})
			for op, err := range map[string]error{"load": loadErr, "save": saveErr} {
				if ok || !errors.Is(err, ErrUnsafePath) || !strings.Contains(err.Error(), strconv.Quote(dir)) {
					t.Errorf("%s: ok=%v err=%v; want ErrUnsafePath naming %q", op, ok, err, dir)
				}
			}
		})
	}
}

func TestSaveCalibrationRefuses(t *testing.T) {
	tests := []struct {
		name string
		key  string
		c    Calibration
		want error
	}{
		{"key not a hash", "../" + calKeyA[3:], Calibration{At: calAt, Result: json.RawMessage(`{}`)}, ErrInvalidID},
		{"upper-case key", strings.ToUpper(calKeyA), Calibration{At: calAt, Result: json.RawMessage(`{}`)}, ErrInvalidID},
		{"no time", calKeyA, Calibration{Result: json.RawMessage(`{}`)}, ErrInvalidID},
		{"invalid JSON", calKeyA, Calibration{At: calAt, Result: json.RawMessage(`{`)}, ErrInvalidID},
		{"not an object", calKeyA, Calibration{At: calAt, Result: json.RawMessage(`"x"`)}, ErrInvalidID},
		{"too large", calKeyA, Calibration{At: calAt, Result: json.RawMessage(`{"x":"` + strings.Repeat("a", MaxCalibrationBytes) + `"}`)}, ErrTooLarge},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := openStore(t)
			if err := s.SaveCalibration(tt.key, tt.c); !errors.Is(err, tt.want) {
				t.Fatalf("err = %v; want %v", err, tt.want)
			}
			if _, err := os.Stat(filepath.Join(s.dir, calibrationsDir)); !os.IsNotExist(err) {
				t.Errorf("refused save left %s behind: %v", calibrationsDir, err)
			}
		})
	}
}

func TestCalibrationFileModes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission bits are not ACLs on Windows")
	}
	s := openStore(t)
	saveCal(t, s, calKeyA)
	for path, want := range map[string]os.FileMode{
		filepath.Join(s.dir, calibrationsDir): dirMode,
		calPath(s, calKeyA):                   fileMode,
	} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != want {
			t.Errorf("%s mode = %o; want %o", path, got, want)
		}
	}
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, fileMode); err != nil { //nolint:gosec // G703: the test plants files in its own temp store on purpose
		t.Fatal(err)
	}
}
