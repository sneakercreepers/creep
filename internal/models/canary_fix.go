package models

import (
	"slices"
	"strings"
)

// canaryFix names what to change in a known CLI's command line when the
// canary caught it using tools. Presets (#7) own full command lines; this
// only knows the flags that switch tools on or off.
func canaryFix(program string, args []string) string {
	switch program {
	case "claude":
		return claudeFix(args)
	case "gemini":
		return removeFix(args, "--yolo", "-y", "--approval-mode")
	case "codex":
		if hasValue(args, "read-only", "--sandbox", "-s") {
			return "it already has --sandbox read-only; check ~/.codex/config.toml for tools or MCP servers"
		}
		return "add --sandbox read-only to the codex exec command"
	case "llm":
		return removeFix(args, "-T", "--tool", "--functions", "--td", "--tools-debug")
	case "ollama":
		return "ollama run has no tools; check that model.run is not a wrapper script"
	}
	return "turn off every tool of this CLI (file writes, shell, MCP servers) in model.run"
}

// claudeFix names the missing flags of claude -p.
func claudeFix(args []string) string {
	var missing []string
	if !hasValue(args, "", "--tools") {
		missing = append(missing, `--tools ""`)
	}
	if !slices.Contains(args, "--strict-mcp-config") {
		missing = append(missing, "--strict-mcp-config")
	}
	if len(missing) == 0 {
		return `it already has --tools "" and --strict-mcp-config; check ~/.claude settings and hooks`
	}
	return "add " + strings.Join(missing, " and ") + " to the claude command"
}

// removeFix names the tool-enabling flags present in args.
func removeFix(args []string, flags ...string) string {
	var found []string
	for _, a := range args {
		name, _, _ := strings.Cut(a, "=")
		if slices.Contains(flags, name) && !slices.Contains(found, name) {
			found = append(found, name)
		}
	}
	if len(found) == 0 {
		return "no tool flag (" + strings.Join(flags, ", ") + ") is set; check the CLI's settings for tools or MCP servers"
	}
	return "remove " + strings.Join(found, " and ") + " from model.run"
}

// hasValue reports whether a flag in names is followed by value, as
// "--flag value" or "--flag=value".
func hasValue(args []string, value string, names ...string) bool {
	for i, a := range args {
		if slices.Contains(names, a) && i+1 < len(args) && args[i+1] == value {
			return true
		}
		name, v, ok := strings.Cut(a, "=")
		if ok && slices.Contains(names, name) && v == value {
			return true
		}
	}
	return false
}
