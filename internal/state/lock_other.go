//go:build !windows && (!unix || solaris || aix)

package state

import (
	"errors"
	"os"
)

// lockOpen fails closed where creep has no non-blocking file lock from the
// standard library: running without one could interleave two runs' logs.
func (s *Store) lockOpen(string) (*os.File, error) {
	return nil, errors.New("no inter-process file lock on this platform")
}
