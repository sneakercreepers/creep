//go:build !unix

package cli

import "os"

// openForCheck is a plain open: Windows has no FIFOs that block on open, and
// devices such as NUL or CON are rejected by the regular-file check.
func openForCheck(path string) (*os.File, error) {
	return os.Open(path) //nolint:gosec // G703: opening the path the user or CREEP_POLICY names is the point; checkConfigPath vets it first
}

// openInRoot opens name inside root; see openForCheck for why a plain open
// is enough here.
func openInRoot(root *os.Root, name string) (*os.File, error) {
	return root.Open(name)
}

func restoreBlocking(*os.File) error { return nil }
