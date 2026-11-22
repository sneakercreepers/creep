package sandbox

import (
	"regexp"
	"slices"
	"strings"
)

// The build runs with --network=none, which binds only RUN steps. The
// builder itself still fetches what an instruction names: a URL or git
// repository in ADD, a frontend image in a parser directive, every image
// in FROM, COPY --from and RUN --mount from= (Docker pulls a missing one
// even with --pull=false), and the layers of a platform the local image
// lacks. checkDockerfile is an allowlist: it accepts only a form it reads
// exactly as BuildKit (Docker) and Buildah (Podman) both do, and refuses
// everything else; the images it returns must then be present locally, so
// the builder never pulls.
//
// The accepted form:
//   - bytes: printable ASCII, tab and line feed; a carriage return only
//     right before a line feed (both line scanners drop it there). So no
//     BOM, no \v, \f or lone \r, and the only white space inside a line is
//     space and tab, which every reader splits on alike;
//   - no parser directive in any form: no "//" line, no "# key=" line
//     anywhere, no JSON directive, so the escape character is always "\";
//   - a line continues only on one backslash at its end: a line ending in
//     two is refused, since BuildKit ends it and Buildah continues it;
//   - only the instructions in instructionFlags, keywords in any case, each
//     with only its own flags, and no quote or backslash in a flag; no
//     ONBUILD, whose trigger would run unchecked in a later FROM;
//   - per instruction, only the arguments checkInstruction reads; anything
//     it does not understand is refused, not skipped.
//
// Heredoc bodies are read as instructions too, which refuses more, never
// less.

// Dockerfile rules, reported as the refusal's detail.
const (
	ruleCharacter     = "character"        // a byte outside the accepted form
	ruleDirective     = "parser_directive" // # key= or //: a frontend, an escape character, a platform
	ruleContinuation  = "continuation"     // a line ending in two backslashes: the builders join it differently
	ruleInstruction   = "instruction"      // a keyword outside the list the check reads
	ruleRemoteAdd     = "remote_add"       // an ADD source that is not plainly a local path
	ruleVariableImage = "variable_image"   // FROM, --from or from= with a variable: no image to check
	ruleImageName     = "image_name"       // not a plain image reference, or one the engine could read as an image ID
	rulePlatform      = "platform"         // a foreign platform would pull its layers
	ruleGlobalArg     = "global_arg"       // an ARG before FROM that is not one bare name: the builder reads it
	ruleFlag          = "flag"             // a flag outside the instruction's list, or quoted
	ruleMount         = "mount"            // a --mount type that outlives the build, an unknown key, a source above its root
	ruleOnbuild       = "onbuild"          // a trigger runs in a later FROM, unchecked
	ruleStageName     = "stage_name"       // a stage name BuildKit refuses, or one defined twice
	ruleJSON          = "json"             // an exec form that is not a plain JSON array of strings
	ruleTooManyImages = "too_many_images"  // more images than the check covers
	ruleNoFrom        = "no_from"          // nothing to build
	ruleHeredoc       = "heredoc"          // a here-document: its body is not instructions, and its end line is the author's
)

const maxBaseImages = 16

var (
	// anyDirective is a "# key=" comment in any spacing or case: BuildKit
	// reads directives as `#\s*key\s*=`, so this matches every one of them.
	anyDirective = regexp.MustCompile(`^#\s*[A-Za-z][A-Za-z0-9_-]*\s*=`)
	// continuation is BuildKit's own rule: a backslash after another one
	// does not continue, so `x\\` ends its line (v0.2 release pentest F1).
	continuation = regexp.MustCompile(`(^|[^\\])\\[ \t]*$`)
	// doubleBackslashEnd is a line Buildah continues and BuildKit does not.
	doubleBackslashEnd = regexp.MustCompile(`\\\\[ \t]*$`)
)

// checkDockerfile returns the images the build reads and the stage names,
// or the rule that refuses the file.
func checkDockerfile(data []byte) (images, stages []string, rule string) {
	text, ok := plainText(data)
	if !ok {
		return nil, nil, ruleCharacter
	}
	lines := strings.Split(text, "\n")
	if hasDirective(text, lines) {
		return nil, nil, ruleDirective
	}
	if slices.ContainsFunc(lines, doubleBackslashEnd.MatchString) {
		return nil, nil, ruleContinuation
	}
	images, stages, rule = checkInstructions(logicalLines(lines))
	if rule != "" {
		return nil, nil, rule
	}
	slices.Sort(images)
	if images = slices.Compact(images); len(images) > maxBaseImages {
		return nil, nil, ruleTooManyImages
	}
	return images, stages, ""
}

// plainText accepts printable ASCII, tab and line feed, and a carriage
// return only before a line feed, which it drops.
func plainText(data []byte) (string, bool) {
	var b strings.Builder
	for i, c := range data {
		switch {
		case c == '\r' && i+1 < len(data) && data[i+1] == '\n':
			continue
		case c == '\t', c == '\n', c >= 0x20 && c <= 0x7e:
			b.WriteByte(c)
		default:
			return "", false
		}
	}
	return b.String(), true
}

// hasDirective finds a parser directive in any form BuildKit or Buildah
// reads, and anywhere in the file, not only at the top: a "# key="
// comment, a "//" line, or a JSON document.
func hasDirective(text string, lines []string) bool {
	if strings.HasPrefix(strings.TrimLeft(text, " \t\n"), "{") {
		return true
	}
	for _, l := range lines {
		l = strings.TrimLeft(l, " \t")
		if strings.HasPrefix(l, "//") || anyDirective.MatchString(l) {
			return true
		}
	}
	return false
}

// logicalLines joins continued lines ("\" is the only escape character,
// since no directive is accepted) and drops comments and blank lines,
// inside continuations too, as BuildKit and Buildah do: with nothing
// between the pieces, so `AD\` then `D http://…` is one ADD (PR #307
// review).
func logicalLines(lines []string) []string {
	var out []string
	var cur strings.Builder
	open := false
	for _, l := range lines {
		trimmed := strings.TrimSpace(l)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if m := continuation.FindStringSubmatchIndex(l); m != nil {
			cur.WriteString(l[:m[3]])
			open = true
			continue
		}
		cur.WriteString(l)
		out = append(out, strings.TrimSpace(cur.String()))
		cur.Reset()
		open = false
	}
	if open {
		out = append(out, strings.TrimSpace(cur.String()))
	}
	return out
}
