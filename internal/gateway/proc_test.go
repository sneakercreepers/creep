package gateway

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// Security (#6 review M1, L2; #226): a background child the CLI leaves
// behind is killed with its process group, after a normal exit, a timeout
// and the output cap, before the working directory is checked, so it can
// neither write late nor outlive the run. On Windows taskkill /T kills the
// tree on timeout and cap; after a normal exit taskkill finds no tree, so
// nothing is killed there (residual, threat model C3).
func TestExecKillsProcessTree(t *testing.T) {
	tests := []struct {
		mode    string
		timeout time.Duration
		want    error
		unix    bool // the case needs a process group
	}{
		{"spawn", 10 * time.Second, nil, true},
		{"spawnhang", time.Second, ErrCommandTimeout, false},
		{"spawnhuge", 10 * time.Second, ErrResponseTooLarge, false},
	}
	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			if tt.unix && runtime.GOOS == "windows" {
				t.Skip("no process group on Windows: a helper of a CLI that exited normally is a residual")
			}
			mark := filepath.Join(t.TempDir(), "late-mark")
			opts := fakeOptions(t, tt.mode, tt.timeout)
			getenv := opts.Getenv
			opts.Env = append(opts.Env, fakeMarkEnv)
			opts.Getenv = func(k string) string {
				if k == fakeMarkEnv {
					return mark
				}
				return getenv(k)
			}
			c, err := NewCommand(opts)
			if err != nil {
				t.Fatal(err)
			}
			l := openLog(t, runDir(t))
			_, err = l.Exec(context.Background(), c, commandCall(c, "x"))
			if (tt.want == nil && err != nil) || (tt.want != nil && !errors.Is(err, tt.want)) {
				t.Fatalf("Exec = %v, want %v", err, tt.want)
			}
			if _, err := os.Stat(mark); err != nil {
				t.Fatalf("the background child never started: %v", err)
			}
			if helperBeating(t, mark) {
				t.Errorf("the background child outlived the run and still writes %s", mark)
			}
		})
	}
}

// helperBeating reports whether a helper still rewrites beat. Exec returns
// only after the kill, so the check does not depend on how long the kill
// took: the file is removed, a settle lets a write already in flight land,
// it is removed again, and a live helper recreates it within the window.
func helperBeating(t *testing.T, beat string) bool {
	t.Helper()
	for _, wait := range []time.Duration{200 * time.Millisecond, 300 * time.Millisecond} {
		removeBeat(t, beat)
		time.Sleep(wait)
	}
	_, err := os.Stat(beat)
	return err == nil
}

// removeBeat removes beat, retrying while a writer holds it open, which
// Windows refuses to delete.
func removeBeat(t *testing.T, beat string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		err := os.Remove(beat)
		if err == nil || os.IsNotExist(err) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("remove %s: %v", beat, err)
		}
		time.Sleep(beatEvery)
	}
}
