package gateway

import (
	"fmt"
	"strings"
)

// shellOnly are characters that mean something to a shell. creep runs no
// shell, so outside quotes they are refused rather than passed on literally:
// a user writing "claude -p | jq" must learn it does not pipe.
const shellOnly = "$`|;&<>()*?~#{}[]!"

// splitCommandLine splits a command line into argv without a shell. Space
// and tab separate arguments; '...' and "..." group text literally, with no
// escapes or expansion, and "" is an empty argument (claude --tools "").
// Control characters, shell syntax outside quotes and unterminated quotes
// are errors.
func splitCommandLine(s string) ([]string, error) {
	if len(s) > maxCommandBytes {
		return nil, fmt.Errorf("%w: command line over %d bytes", ErrCommand, maxCommandBytes)
	}
	var argv []string
	var cur strings.Builder
	inArg, quote := false, rune(0)
	for _, r := range s {
		switch {
		case r < ' ' && r != '\t', r == 0x7f:
			return nil, fmt.Errorf("%w: control character in command line", ErrCommand)
		case quote != 0 && r == quote:
			quote = 0
		case quote != 0:
			cur.WriteRune(r)
		case r == '\'' || r == '"':
			quote, inArg = r, true
		case r == ' ' || r == '\t':
			if inArg {
				argv, inArg = append(argv, cur.String()), false
				cur.Reset()
			}
		case strings.ContainsRune(shellOnly, r):
			return nil, fmt.Errorf("%w: %q is shell syntax and creep runs no shell; quote it to pass it literally", ErrCommand, r)
		default:
			cur.WriteRune(r)
			inArg = true
		}
	}
	return finishArgv(argv, cur.String(), inArg, quote)
}

func finishArgv(argv []string, last string, inArg bool, quote rune) ([]string, error) {
	if quote != 0 {
		return nil, fmt.Errorf("%w: unterminated quote", ErrCommand)
	}
	if inArg {
		argv = append(argv, last)
	}
	switch {
	case len(argv) == 0 || argv[0] == "":
		return nil, fmt.Errorf("%w: empty command", ErrCommand)
	case len(argv) > maxCommandArgs:
		return nil, fmt.Errorf("%w: more than %d arguments", ErrCommand, maxCommandArgs)
	}
	return argv, nil
}
