// Command openprobe is built by TestOpenWithSecretRefusedOutsideTests as an
// ordinary (non-test) binary. It reaches state.OpenWithSecret every way a
// production file could and prints one line per attempt, so the test can
// prove each is refused. It is test data: the go command never builds
// testdata on its own.
package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/sneakercreepers/creep/internal/state"
	sa "github.com/sneakercreepers/creep/internal/state"
)

func main() {
	dir := filepath.Join(os.Args[1], ".creep")
	key := bytes.Repeat([]byte{'Z'}, state.SecretBytes)
	open := sa.OpenWithSecret
	attempts := []struct {
		name string
		call func() (*state.Store, error)
	}{
		{"direct", func() (*state.Store, error) { return state.OpenWithSecret(dir, key) }},
		{"second import", func() (*state.Store, error) { return sa.OpenWithSecret(dir, key) }},
		{"function value", func() (*state.Store, error) { return open(dir, key) }},
	}
	for _, a := range attempts {
		s, err := a.call()
		if s != nil {
			_ = s.Close()
		}
		fmt.Printf("%s: refused=%v\n", a.name, s == nil && errors.Is(err, state.ErrTestOnly))
	}
}
