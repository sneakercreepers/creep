package sandbox

import (
	"encoding/json"
	"regexp"
	"slices"
	"strings"
)

// The build runs with --network=none, which binds only RUN steps. The
// builder itself still fetches what an instruction names: a URL or git
// repository in ADD, a frontend image in a parser directive, and every
// image in FROM, COPY --from and RUN --mount from= (Docker pulls a missing
// one even with --pull=false). checkDockerfile is an allowlist: it accepts
// only a lexical form it reads exactly as BuildKit does, refuses every
// parser directive, and returns the images, which must then be present
// locally, so the builder never pulls.
//
// The accepted form:
//   - bytes: printable ASCII, tab and line feed; a carriage return only
//     right before a line feed (BuildKit's line scanner drops it there). So
//     no BOM, no \v, \f or lone \r, and the only white space inside a line
//     is space and tab, which both readers split on alike;
//   - no parser directive in any form: no "//" line, no "# key=" line
//     anywhere, no JSON directive, so the escape character is always "\";
//   - instruction keywords and flag names in any case; flags only from a
//     list per instruction, with no quote or backslash in them;
//   - no ONBUILD, whose trigger would run unchecked in a later FROM; mounts
//     only of a type that leaves nothing behind (mountTypes);
//   - a stage reference only to an earlier stage: by name, or in --from and
//     from= by an index below the number of earlier stages; anything else
//     is an image.
//
// Heredoc bodies are read as instructions too, which refuses more, never
// less.

// Dockerfile rules, reported as the refusal's detail.
const (
	ruleCharacter     = "character"        // a byte outside the accepted form
	ruleDirective     = "parser_directive" // # key= or //: a frontend, an escape character
	ruleRemoteAdd     = "remote_add"       // ADD of a URL or git repository: fetched outside --network=none
	ruleVariableImage = "variable_image"   // FROM, --from or from= with a variable: no image to check
	ruleImageName     = "image_name"       // not a plain image reference
	rulePlatform      = "platform"         // FROM for another platform would pull it
	ruleFlag          = "flag"             // a flag outside the instruction's list, or quoted
	ruleMount         = "mount"            // a --mount type that outlives the build, or a source above its root
	ruleOnbuild       = "onbuild"          // a trigger runs in a later FROM, unchecked
	ruleTooManyImages = "too_many_images"  // more images than the check covers
	ruleNoFrom        = "no_from"          // nothing to build
)

const maxBaseImages = 16

var (
	// anyDirective is a "# key=" comment in any spacing or case: BuildKit
	// reads directives as `#\s*key\s*=`, so this matches every one of them.
	anyDirective = regexp.MustCompile(`^#\s*[A-Za-z][A-Za-z0-9_-]*\s*=`)
	continuation = regexp.MustCompile(`\\[ \t]*$`)
	// imageRef is a plain reference: no flag, variable or space.
	imageRef       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/:@-]{0,254}$`)
	nativePlatform = []string{"$BUILDPLATFORM", "${BUILDPLATFORM}", "$TARGETPLATFORM", "${TARGETPLATFORM}"}
)

// allowedFlags are the flags each instruction may carry, by lower-case
// name. RUN has no --network, --security or --device; ADD has no flag
// that only a remote source uses.
var allowedFlags = map[string][]string{
	"FROM": {"platform"},
	"RUN":  {"mount"},
	"COPY": {"from", "chown", "chmod", "link", "parents", "exclude"},
	"ADD":  {"chown", "chmod", "link", "exclude"},
}

// booleanFlags may stand alone, as BuildKit reads them: --link is --link=true.
var booleanFlags = []string{"link", "parents"}

// mountTypes leave nothing behind and read only the staged context or an
// earlier stage. A cache mount outlives --no-cache, Close and creep clean,
// so a later build of the operator's would read what this one wrote; a
// secret or ssh mount has nothing to offer a build that gets none.
var mountTypes = []string{"bind", "tmpfs"}

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

// hasDirective finds a parser directive in any form BuildKit reads, and
// anywhere in the file, not only at the top: a "# key=" comment, a "//"
// line, or a JSON document.
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
// inside continuations too, as BuildKit does.
func logicalLines(lines []string) []string {
	var out []string
	var cur strings.Builder
	open := false
	for _, l := range lines {
		trimmed := strings.TrimSpace(l)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if loc := continuation.FindStringIndex(l); loc != nil {
			cur.WriteString(l[:loc[0]] + " ")
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

// stageSet is what earlier FROM instructions defined.
type stageSet struct {
	names []string // lower case
	count int      // FROM instructions so far: indices below it are stages
}

// checkInstructions walks the instructions in order, so a stage is known
// before a later reference uses it.
func checkInstructions(lines []string) (images, stages []string, rule string) {
	var st stageSet
	for _, l := range lines {
		keyword, rest := splitKeyword(l)
		keyword = strings.ToUpper(keyword)
		flags, args, rule := parseFlags(keyword, rest)
		if rule != "" {
			return nil, nil, rule
		}
		imgs, rule := checkInstruction(keyword, flags, args, &st)
		if rule != "" {
			return nil, nil, rule
		}
		images = append(images, imgs...)
	}
	if st.count == 0 {
		return nil, nil, ruleNoFrom
	}
	return images, st.names, ""
}

func checkInstruction(keyword string, flags map[string][]string, args []string, st *stageSet) ([]string, string) {
	switch keyword {
	case "FROM":
		return checkFrom(flags, args, st)
	case "ADD":
		return nil, checkAdd(args)
	case "COPY":
		return eachValue(flags["from"], st, stageOrImage)
	case "RUN":
		return eachValue(flags["mount"], st, mountFrom)
	case "ONBUILD":
		return nil, ruleOnbuild
	}
	return nil, ""
}

// eachValue checks every value of a flag, which may be given more than
// once (RUN --mount).
func eachValue(values []string, st *stageSet, check func(string, *stageSet) ([]string, string)) ([]string, string) {
	var images []string
	for _, v := range values {
		imgs, rule := check(v, st)
		if rule != "" {
			return nil, rule
		}
		images = append(images, imgs...)
	}
	return images, ""
}

// splitKeyword cuts the keyword off at the first space or tab, the only
// white space the accepted form has.
func splitKeyword(l string) (keyword, rest string) {
	i := strings.IndexAny(l, " \t")
	if i < 0 {
		return l, ""
	}
	return l[:i], l[i+1:]
}

// parseFlags splits the leading --name=value flags (names in lower case)
// from the arguments. A flag not in the instruction's list, without a
// value or with a quote or backslash in it is refused.
func parseFlags(keyword, rest string) (map[string][]string, []string, string) {
	fields := strings.Fields(rest)
	flags := map[string][]string{}
	i := 0
	for ; i < len(fields) && strings.HasPrefix(fields[i], "--"); i++ {
		name, value, ok := strings.Cut(fields[i][2:], "=")
		name = strings.ToLower(name)
		if !ok && slices.Contains(booleanFlags, name) {
			value, ok = "true", true
		}
		if !ok || strings.ContainsAny(fields[i], "\"'\\") {
			return nil, nil, ruleFlag
		}
		if allowed, listed := allowedFlags[keyword]; listed && !slices.Contains(allowed, name) {
			return nil, nil, ruleFlag
		}
		flags[name] = append(flags[name], value)
	}
	return flags, fields[i:], ""
}

// checkFrom reads FROM [--platform=P] image [AS name]. FROM names an
// earlier stage only by name: a number is an image.
func checkFrom(flags map[string][]string, args []string, st *stageSet) ([]string, string) {
	for _, p := range flags["platform"] {
		if !slices.Contains(nativePlatform, p) {
			return nil, rulePlatform
		}
	}
	var stage string
	switch {
	case len(args) == 3 && strings.EqualFold(args[1], "AS") && stageName.MatchString(args[2]):
		stage = strings.ToLower(args[2])
	case len(args) != 1:
		return nil, ruleImageName
	}
	ref, lower := args[0], strings.ToLower(args[0])
	var imgs []string
	var rule string
	if lower != "scratch" && !slices.Contains(st.names, lower) {
		imgs, rule = image(ref)
	}
	st.count++
	if stage != "" {
		st.names = append(st.names, stage)
	}
	return imgs, rule
}

// stageOrImage is a --from or from= value: an earlier stage by name or
// index, else an image.
func stageOrImage(ref string, st *stageSet) ([]string, string) {
	if slices.Contains(st.names, strings.ToLower(ref)) || isIndexBelow(ref, st.count) {
		return nil, ""
	}
	return image(ref)
}

func image(ref string) ([]string, string) {
	switch {
	case strings.Contains(ref, "$"):
		return nil, ruleVariableImage
	case !imageRef.MatchString(ref):
		return nil, ruleImageName
	}
	return []string{ref}, ""
}

// checkAdd refuses a source the builder would fetch: a URL, a git remote
// (scp-like user@host:path too) or a variable that could expand to one.
func checkAdd(args []string) string {
	if joined := strings.Join(args, " "); strings.HasPrefix(joined, "[") {
		args = jsonArgs(joined)
	}
	if len(args) > 0 {
		args = args[:len(args)-1] // the destination
	}
	for _, src := range args {
		if strings.Contains(src, "://") || strings.HasPrefix(src, "git@") || strings.Contains(src, "$") ||
			(strings.Contains(src, "@") && strings.Contains(src, ":")) {
			return ruleRemoteAdd
		}
	}
	return ""
}

// mountFrom checks a --mount value: keys in any case, a type from
// mountTypes only (bind when none is given), from= an earlier stage or an
// image, source= never above its root.
func mountFrom(spec string, st *stageSet) ([]string, string) {
	var images []string
	for _, kv := range strings.Split(spec, ",") {
		key, value, _ := strings.Cut(kv, "=")
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "type":
			if !slices.Contains(mountTypes, value) {
				return nil, ruleMount
			}
		case "from":
			imgs, rule := stageOrImage(value, st)
			if rule != "" {
				return nil, rule
			}
			images = append(images, imgs...)
		case "source", "src":
			if value == ".." || strings.HasPrefix(value, "../") || strings.Contains(value, "/../") || strings.HasSuffix(value, "/..") {
				return nil, ruleMount
			}
		}
	}
	return images, ""
}

// jsonArgs reads the exec form ["src", ..., "dest"].
func jsonArgs(joined string) []string {
	var args []string
	if err := json.Unmarshal([]byte(joined), &args); err != nil {
		return strings.Fields(joined) // not valid JSON: Docker reads it as the shell form
	}
	return args
}

func isIndexBelow(s string, n int) bool {
	if s == "" || len(s) > 4 {
		return false
	}
	i := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
		i = i*10 + int(r-'0')
	}
	return i < n
}
