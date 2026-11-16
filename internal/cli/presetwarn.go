package cli

import (
	"fmt"
	"io"

	"github.com/sneakercreepers/creep/internal/config"
	"github.com/sneakercreepers/creep/internal/presets"
)

// warnHostReads tells the operator, before anything is sent, that the
// selected preset's CLI can still read the host. The tool canary only sees
// writes and commands that leave files, so it cannot catch this; a prompt
// injection in scanned code could make the CLI read a secret and put it in
// a prompt to its provider, past creep's redaction.
func warnHostReads(w io.Writer, m config.Model) {
	if m.Preset == "" {
		return
	}
	p, err := presets.Lookup(m.Preset)
	if err != nil || p.HostReads != presets.HostReadsUnbounded {
		return
	}
	msg := fmt.Sprintf("warning: preset %q can read files outside its empty working directory: %s. "+
		"Scanned code could steer it to read host secrets and send them to the model provider unredacted; "+
		"for untrusted code prefer the claude-code or ollama preset", p.Name, p.HostReadsDetail)
	fmt.Fprintln(w, escapeControl(msg))
}
