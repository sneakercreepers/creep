//go:build unix

package gateway

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Security (#6 review M1, L2): a background child the CLI leaves behind is
// killed with its process group, after a normal exit and after a timeout,
// before the working directory is checked, so it can neither write late
// nor outlive the run.
func TestExecKillsProcessTree(t *testing.T) {
	tests := []struct {
		mode    string
		timeout time.Duration
		want    error
	}{
		{"spawn", 10 * time.Second, nil},
		{"spawnhang", time.Second, ErrCommandTimeout}, // killed before the child writes
	}
	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
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
			time.Sleep(4 * time.Second) // past the child's 3 s delay
			if _, err := os.Stat(mark); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("the background child outlived the run and wrote %s (%v)", mark, err)
			}
		})
	}
}
