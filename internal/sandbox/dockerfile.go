package sandbox

import (
	"bytes"
	"encoding/json"
	"regexp"
	"slices"
	"strings"
)

// The build runs with --network=none, which binds only RUN steps. The
// builder itself still fetches what an instruction names: a URL or git
// repository in ADD, a frontend image in "# syntax=", and every image in
// FROM, COPY --from and RUN --mount from=. checkDockerfile refuses the
// first three and returns the images, which must then be present locally,
// so the builder never pulls.
//
// It reads the file as Docker does (instructions, line continuations,
// comments inside them) and errs on the side of refusing: logical lines
// are formed once with "\" and once with "`" as the escape character, so
// an escape directive cannot hide an instruction, and heredoc bodies are
// read as instructions too.

// Dockerfile rules, reported as the refusal's detail.
const (
	ruleBinary        = "binary"           // a NUL byte: not a Dockerfile
	ruleSyntax        = "syntax_directive" // the frontend image would be pulled
	ruleRemoteAdd     = "remote_add"       // ADD of a URL or git repository: fetched outside --network=none
	ruleVariableImage = "variable_image"   // FROM, --from or from= with a variable: no image to check
	ruleImageName     = "image_name"       // not a plain image reference
	rulePlatform      = "platform"         // FROM for another platform would pull it
	ruleRunOption     = "run_option"       // RUN --network, --security or --device
	ruleTooManyImages = "too_many_images"  // more images than the check covers
	ruleNoFrom        = "no_from"          // nothing to build
)

const maxBaseImages = 16

var (
	directive = regexp.MustCompile(`^#\s*([A-Za-z][A-Za-z0-9_-]*)\s*=`)
	// imageRef is a plain reference: no flag, variable or space.
	imageRef       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/:@-]{0,254}$`)
	continuation   = map[byte]*regexp.Regexp{'\\': regexp.MustCompile(`\\[ \t]*$`), '`': regexp.MustCompile("`[ \t]*$")}
	nativePlatform = []string{"$BUILDPLATFORM", "${BUILDPLATFORM}", "$TARGETPLATFORM", "${TARGETPLATFORM}"}
)

// checkDockerfile returns the images the build reads and the stage names,
// or the rule that refuses the file.
func checkDockerfile(data []byte) (images, stages []string, rule string) {
	if bytes.IndexByte(data, 0) >= 0 {
		return nil, nil, ruleBinary
	}
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	if hasSyntaxDirective(lines) {
		return nil, nil, ruleSyntax
	}
	var all, allStages []string
	for _, esc := range []byte{'\\', '`'} {
		imgs, st, rule := checkInstructions(logicalLines(lines, esc))
		if rule != "" {
			return nil, nil, rule
		}
		all, allStages = append(all, imgs...), append(allStages, st...)
	}
	slices.Sort(all)
	all = slices.Compact(all)
	if len(all) > maxBaseImages {
		return nil, nil, ruleTooManyImages
	}
	slices.Sort(allStages)
	return all, slices.Compact(allStages), ""
}

// hasSyntaxDirective looks at every comment before the first instruction,
// where Docker reads parser directives.
func hasSyntaxDirective(lines []string) bool {
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l != "" && !strings.HasPrefix(l, "#") {
			return false
		}
		if m := directive.FindStringSubmatch(l); m != nil && strings.EqualFold(m[1], "syntax") {
			return true
		}
	}
	return false
}

// logicalLines joins continued lines with esc as the escape character and
// drops comments and blank lines, inside continuations too, as Docker does.
func logicalLines(lines []string, esc byte) []string {
	var out []string
	var cur strings.Builder
	open := false
	for _, l := range lines {
		trimmed := strings.TrimSpace(l)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if loc := continuation[esc].FindStringIndex(l); loc != nil {
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

// checkInstructions walks the instructions in order, so a stage name is
// known before a later --from uses it.
func checkInstructions(lines []string) (images, stages []string, rule string) {
	froms := 0
	for _, l := range lines {
		keyword, rest := splitKeyword(l)
		var imgs []string
		switch strings.ToUpper(keyword) {
		case "FROM":
			froms++
			var stage string
			imgs, stage, rule = checkFrom(rest, stages)
			if stage != "" {
				stages = append(stages, stage)
			}
		case "ADD":
			if rule = checkAdd(rest); rule == "" {
				imgs, rule = fromFlag(rest, stages)
			}
		case "COPY":
			imgs, rule = fromFlag(rest, stages)
		case "RUN":
			imgs, rule = checkRun(rest, stages)
		}
		if rule != "" {
			return nil, nil, rule
		}
		images = append(images, imgs...)
	}
	if froms == 0 {
		return nil, nil, ruleNoFrom
	}
	return images, stages, ""
}

// checkFrom reads FROM [--platform=P] image [AS name].
func checkFrom(rest string, stages []string) (images []string, stage, rule string) {
	flags, args := splitFlags(rest)
	for _, f := range flags {
		name, value, _ := strings.Cut(f, "=")
		if name == "--platform" && !slices.Contains(nativePlatform, value) {
			return nil, "", rulePlatform
		}
	}
	if len(args) == 0 {
		return nil, "", ruleImageName
	}
	if len(args) == 3 && strings.EqualFold(args[1], "AS") {
		if !stageName.MatchString(args[2]) {
			return nil, "", ruleImageName
		}
		stage = strings.ToLower(args[2])
	} else if len(args) != 1 {
		return nil, "", ruleImageName
	}
	imgs, rule := imageUse(args[0], stages)
	return imgs, stage, rule
}

// imageUse is one image an instruction reads: an earlier stage, scratch or
// a stage index need nothing; anything else must be a plain reference.
func imageUse(ref string, stages []string) ([]string, string) {
	lower := strings.ToLower(ref)
	switch {
	case strings.Contains(ref, "$"):
		return nil, ruleVariableImage
	case lower == "scratch" || slices.Contains(stages, lower) || isDigits(ref):
		return nil, ""
	case !imageRef.MatchString(ref):
		return nil, ruleImageName
	}
	return []string{ref}, ""
}

// checkAdd refuses a source the builder would fetch: a URL, a git remote
// (scp-like user@host:path too) or a variable that could expand to one.
func checkAdd(rest string) string {
	_, args := splitFlags(rest)
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

// fromFlag checks COPY --from (and ADD's) image.
func fromFlag(rest string, stages []string) ([]string, string) {
	flags, _ := splitFlags(rest)
	for _, f := range flags {
		if v, ok := strings.CutPrefix(f, "--from="); ok {
			return imageUse(v, stages)
		}
	}
	return nil, ""
}

// checkRun refuses RUN options that ask for a network, privileges or a
// device, and checks the image of each --mount from=.
func checkRun(rest string, stages []string) ([]string, string) {
	flags, _ := splitFlags(rest)
	var images []string
	for _, f := range flags {
		name, value, _ := strings.Cut(f, "=")
		switch name {
		case "--network":
			if value != "none" {
				return nil, ruleRunOption
			}
		case "--security", "--device":
			return nil, ruleRunOption
		case "--mount":
			imgs, rule := mountFrom(value, stages)
			if rule != "" {
				return nil, rule
			}
			images = append(images, imgs...)
		}
	}
	return images, ""
}

func mountFrom(spec string, stages []string) ([]string, string) {
	for _, kv := range strings.Split(spec, ",") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(kv), "from="); ok {
			return imageUse(v, stages)
		}
	}
	return nil, ""
}

// splitKeyword cuts the instruction keyword off at the first space or tab.
func splitKeyword(l string) (keyword, rest string) {
	i := strings.IndexAny(l, " 	")
	if i < 0 {
		return l, ""
	}
	return l[:i], l[i+1:]
}

// splitFlags splits an instruction's arguments into its leading --flags
// and the rest, on white space.
func splitFlags(rest string) (flags, args []string) {
	fields := strings.Fields(rest)
	i := 0
	for i < len(fields) && strings.HasPrefix(fields[i], "--") {
		i++
	}
	return fields[:i], fields[i:]
}

// jsonArgs reads the exec form ["src", ..., "dest"] after any flags.
func jsonArgs(joined string) []string {
	var args []string
	if err := json.Unmarshal([]byte(joined), &args); err != nil {
		return strings.Fields(joined) // not valid JSON: Docker reads it as the shell form
	}
	return args
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
