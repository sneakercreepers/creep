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
// behind is killed with its process group, after a normal exit and after a
// timeout, before the working directory is checked, so it can neither
// write late nor outlive the run. On Windows taskkill /T kills the tree on
// timeout; after a normal exit the CLI's ID is free and may be reused, so
// nothing is killed there (residual, threat model C3).
func TestExecKillsProcessTree(t *testing.T) {
	tests := []struct {
		mode    string
		timeout time.Duration
		want    error
		unix    bool // the case needs a process group
	}{
		{"spawn", 10 * time.Second, nil, true},
		{"spawnhang", time.Second, ErrCommandTimeout, false}, // killed before the child writes
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
			time.Sleep(7 * time.Second) // past the child's 6 s delay
			if _, err := os.Stat(mark); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("the background child outlived the run and wrote %s (%v)", mark, err)
			}
		})
	}
}
