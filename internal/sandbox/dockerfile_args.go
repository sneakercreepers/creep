package sandbox

import (
	"encoding/json"
	"slices"
	"strings"
)

// checkFrom reads FROM [--platform=P] image [AS name].
func checkFrom(flags map[string][]string, args []string, st *stageSet) ([]string, string) {
	for _, p := range flags["platform"] {
		if !slices.Contains(nativePlatform, p) {
			return nil, rulePlatform
		}
	}
	stage, rule := newStageName(args, st)
	if rule != "" {
		return nil, rule
	}
	imgs, rule := fromBase(args[0], st)
	if rule != "" {
		return nil, rule
	}
	st.count++
	if stage != "" {
		st.names = append(st.names, stage)
	}
	return imgs, ""
}

// newStageName reads the optional "AS name": a name BuildKit accepts and
// no earlier stage has.
func newStageName(args []string, st *stageSet) (string, string) {
	switch {
	case len(args) == 1:
		return "", ""
	case len(args) != 3 || !strings.EqualFold(args[1], "AS"):
		return "", ruleImageName
	}
	name := strings.ToLower(args[2])
	if !dockerfileStage.MatchString(name) || slices.Contains(st.names, name) {
		return "", ruleStageName
	}
	return name, ""
}

// fromBase is a FROM reference: an earlier stage, scratch or an image.
// BuildKit matches it against the (lower-case) stage names as written, so
// `FROM Build` is not stage build; a reference that differs from a stage
// name only in case is refused. FROM never names a stage by index.
func fromBase(ref string, st *stageSet) ([]string, string) {
	switch {
	case slices.Contains(st.names, ref), ref == "scratch":
		return nil, ""
	case slices.Contains(st.names, strings.ToLower(ref)):
		return nil, ruleStageName
	}
	return image(ref)
}

// stageOrImage is a COPY --from value: an earlier stage by name (in any
// case) or index, else an image.
func stageOrImage(ref string, st *stageSet) ([]string, string) {
	if slices.Contains(st.names, strings.ToLower(ref)) || isIndexBelow(ref, st.count) {
		return nil, ""
	}
	return image(ref)
}

// stageByNameOrImage is a RUN --mount from= value. BuildKit looks it up
// by name only: from=0 is the image docker.io/library/0, never stage 0.
func stageByNameOrImage(ref string, st *stageSet) ([]string, string) {
	if slices.Contains(st.names, strings.ToLower(ref)) {
		return nil, ""
	}
	return image(ref)
}

func image(ref string) ([]string, string) {
	switch {
	case strings.Contains(ref, "$"):
		return nil, ruleVariableImage
	case !imageRef.MatchString(ref), imageIDLike.MatchString(ref):
		return nil, ruleImageName
	}
	return []string{ref}, ""
}

// checkAdd accepts only sources that are plainly local paths (localSource):
// BuildKit and Buildah fetch a URL or a git remote outside --network=none,
// and their shell lexers drop quotes and escapes (`http:"//"x`), so a
// source is never read as shell. An exec form must be a valid JSON array of
// strings: when it is not, BuildKit falls back to the shell form, which
// this check does not follow.
func checkAdd(args string) string {
	sources, local := strings.Fields(args), localSource
	if strings.HasPrefix(args, "[") {
		var ok bool
		if sources, ok = execForm(args); !ok {
			return ruleJSON
		}
		local = localJSONSource
	}
	if len(sources) > 0 {
		sources = sources[:len(sources)-1] // the destination
	}
	for _, src := range sources {
		if !local.MatchString(src) {
			return ruleRemoteAdd
		}
	}
	return ""
}

// execForm reads an argument list that starts with "[" as a JSON array of
// strings, the whole text and nothing else. ok is false only for such a
// list that is not one; a shell form is returned as its fields.
func execForm(args string) ([]string, bool) {
	if !strings.HasPrefix(args, "[") {
		return strings.Fields(args), true
	}
	var list []any
	if err := json.Unmarshal([]byte(args), &list); err != nil {
		return nil, false
	}
	out := make([]string, 0, len(list))
	for _, v := range list {
		s, ok := v.(string)
		if !ok {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}

// checkMount reads a --mount value: keys from mountKeys in any case, a
// type from mountTypes only (bind when none is given), from= an earlier
// stage by name or an image, source= never above its root, no variable.
func checkMount(spec string, st *stageSet) ([]string, string) {
	var images []string
	for _, kv := range strings.Split(spec, ",") {
		key, value, hasValue := strings.Cut(kv, "=")
		key = strings.ToLower(key)
		switch {
		case !hasValue && slices.Contains(bareMountKeys, key):
			continue
		case !hasValue || !slices.Contains(mountKeys, key):
			return nil, ruleMount
		case key == "from":
			imgs, rule := stageByNameOrImage(value, st)
			if rule != "" {
				return nil, rule
			}
			images = append(images, imgs...)
		case strings.Contains(value, "$"),
			key == "type" && !slices.Contains(mountTypes, value),
			(key == "source" || key == "src") && leavesRoot(value):
			return nil, ruleMount
		}
	}
	return images, ""
}

func leavesRoot(p string) bool {
	return p == ".." || strings.HasPrefix(p, "../") || strings.Contains(p, "/../") || strings.HasSuffix(p, "/..")
}

// checkArg refuses an ARG that could set a platform argument: a global
// ARG with a value replaces BuildKit's own BUILDPLATFORM or
// TARGETPLATFORM, and FROM --platform=$BUILDPLATFORM then fetches that
// platform's layers. An ARG that names a platform is accepted only as one
// bare name, which keeps the builder's value. Before the first FROM, every
// ARG must be one bare name: the builder itself reads global ARGs
// (platforms, SOURCE_DATE_EPOCH, which BuildKit may resolve through a
// remote ADD), and FROM, their only other reader, takes no variable here.
func checkArg(args string, global bool) string {
	if bareArg.MatchString(args) {
		return ""
	}
	plain := strings.NewReplacer(`\`, "", `"`, "", "'", "").Replace(strings.ToUpper(args))
	switch {
	case strings.Contains(plain, "PLATFORM"):
		return rulePlatform
	case global:
		return ruleGlobalArg
	}
	return ""
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
