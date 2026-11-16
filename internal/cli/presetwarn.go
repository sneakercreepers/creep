package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/sneakercreepers/creep/internal/config"
	"github.com/sneakercreepers/creep/internal/presets"
)

// warnPreset tells the operator, in one line before anything is sent, what
// the selected preset does not guarantee. An unverified preset's flags were
// never checked against the real CLI by a maintainer. A preset whose CLI can
// read the host is outside what the tool canary sees (writes and commands
// that leave files): a prompt injection in scanned code could make the CLI
// read a secret and put it in a prompt to its provider, past redaction.
func warnPreset(w io.Writer, m config.Model) {
	if m.Preset == "" {
		return
	}
	p, err := presets.Lookup(m.Preset)
	if err != nil {
		return
	}
	var parts []string
	if !p.IsVerified() {
		parts = append(parts, "is not verified against the real CLI by a maintainer (the tool canary still runs; see CONTRIBUTING.md, Model presets)")
	}
	if p.HostReads == presets.HostReadsUnbounded {
		parts = append(parts, "can read files outside its empty working directory: "+p.HostReadsDetail+
			"; scanned code could steer it to read host secrets and send them unredacted to the model provider, or to any address its web tools reach, outside creep's redaction and egress.log (accepted risk, ADR 0015)")
	}
	if len(parts) == 0 {
		return
	}
	msg := fmt.Sprintf("warning: preset %q %s; for untrusted code prefer the claude-code preset", p.Name, strings.Join(parts, ", and "))
	fmt.Fprintln(w, escapeControl(msg))
}
