package sandbox

import (
	"regexp"
	"slices"
	"strings"
)

// instructionFlags lists every instruction the check reads, by upper-case
// keyword, with the flags each may carry, by lower-case name. Any other
// keyword is refused, ONBUILD included. RUN has no --network, --security
// or --device; ADD has no flag that only a remote source uses.
var instructionFlags = map[string][]string{
	"FROM":        {"platform"},
	"RUN":         {"mount"},
	"COPY":        {"from", "chown", "chmod", "link", "parents", "exclude"},
	"ADD":         {"chown", "chmod", "link", "exclude"},
	"HEALTHCHECK": {"interval", "timeout", "start-period", "start-interval", "retries"},
	"ARG":         nil, "ENV": nil, "LABEL": nil, "WORKDIR": nil, "USER": nil, "EXPOSE": nil, "CMD": nil,
	"ENTRYPOINT": nil, "SHELL": nil, "STOPSIGNAL": nil, "VOLUME": nil, "MAINTAINER": nil,
}

// booleanFlags may stand alone, as BuildKit reads them: --link is --link=true.
var booleanFlags = []string{"link", "parents"}

// mountTypes leave nothing behind and read only the staged context or an
// earlier stage. A cache mount outlives --no-cache, Close and creep clean,
// so a later build of the operator's would read what this one wrote; a
// secret or ssh mount has nothing to offer a build that gets none.
var mountTypes = []string{"bind", "tmpfs"}

// mountKeys are the keys a bind or tmpfs mount takes; bareMountKeys may
// stand alone. Any other key is refused.
var (
	mountKeys     = []string{"type", "from", "source", "src", "target", "dst", "destination", "readonly", "ro", "readwrite", "rw", "size"}
	bareMountKeys = []string{"readonly", "ro", "readwrite", "rw"}
)

var (
	// imageRef is a plain reference: no flag, variable or space.
	imageRef = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/:@-]{0,254}$`)
	// imageIDLike is a reference `image inspect` finds as an image ID or
	// an ID prefix, while the builder reads it as a name on Docker Hub
	// and pulls it (FROM 526f, COPY --from=7, from=0).
	imageIDLike = regexp.MustCompile(`(?i)^(sha256:)?[0-9a-f]+$`)
	// dockerfileStage is BuildKit's rule for a stage name, read in lower case.
	dockerfileStage = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
	// localSource is an ADD source that can only be a local path or
	// pattern: no colon or @ (a URL, a git remote), no # (a git ref), no
	// variable, quote or escape. The exec form also allows a space.
	localSource     = regexp.MustCompile(`^[A-Za-z0-9._/*?+=,%~^\[\]-]+$`)
	localJSONSource = regexp.MustCompile(`^[A-Za-z0-9._/*?+=,%~^\[\] -]+$`)
	nativePlatform  = []string{"$BUILDPLATFORM", "${BUILDPLATFORM}", "$TARGETPLATFORM", "${TARGETPLATFORM}"}
	bareArg         = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

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
		imgs, rule := checkLine(l, &st)
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

// checkLine reads one instruction: a known keyword, its own flags, then
// its arguments.
func checkLine(l string, st *stageSet) ([]string, string) {
	keyword, rest := splitKeyword(l)
	keyword = strings.ToUpper(keyword)
	if keyword == "ONBUILD" {
		return nil, ruleOnbuild
	}
	allowed, known := instructionFlags[keyword]
	if !known {
		return nil, ruleInstruction
	}
	if hasHeredoc(keyword, rest) {
		return nil, ruleHeredoc
	}
	flags, args, rule := parseFlags(allowed, rest)
	if rule != "" {
		return nil, rule
	}
	return checkInstruction(keyword, flags, args, st)
}

// hasHeredoc reports a possible here-document (<<EOF, <<-EOF, 3<<EOF) in
// an instruction that takes one. BuildKit ends its body at the author's
// end word, which may look like a comment or a continuation to this check,
// so a later instruction would be read as body, and a body line as an
// instruction (v0.2 release pentest F2, F3). Any "<<" there is refused,
// inside a shell command too: the check reads lines, not shell, and a
// refused build only leaves findings probable.
func hasHeredoc(keyword, rest string) bool {
	switch keyword {
	case "RUN", "COPY", "ADD":
		return strings.Contains(rest, "<<")
	}
	return false
}

func checkInstruction(keyword string, flags map[string][]string, args string, st *stageSet) ([]string, string) {
	switch keyword {
	case "FROM":
		return checkFrom(flags, strings.Fields(args), st)
	case "ADD":
		return nil, checkAdd(args)
	case "COPY":
		if _, ok := execForm(args); !ok {
			return nil, ruleJSON
		}
		return eachValue(flags["from"], st, stageOrImage)
	case "RUN":
		return eachValue(flags["mount"], st, checkMount)
	case "ARG":
		return nil, checkArg(args, st.count == 0)
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

// parseFlags splits the leading --name=value words (names in lower case)
// from the rest, which it returns as written, as BuildKit does. A flag not
// in allowed, without a value or with a quote or backslash is refused.
func parseFlags(allowed []string, rest string) (map[string][]string, string, string) {
	flags := map[string][]string{}
	for {
		rest = strings.TrimLeft(rest, " \t")
		if !strings.HasPrefix(rest, "--") {
			return flags, rest, ""
		}
		end := strings.IndexAny(rest, " \t")
		if end < 0 {
			end = len(rest)
		}
		word := rest[:end]
		rest = rest[end:]
		name, value, ok := strings.Cut(word[2:], "=")
		name = strings.ToLower(name)
		if !ok && slices.Contains(booleanFlags, name) {
			value, ok = "true", true
		}
		if !ok || strings.ContainsAny(word, "\"'\\") || !slices.Contains(allowed, name) {
			return nil, "", ruleFlag
		}
		flags[name] = append(flags[name], value)
	}
}
