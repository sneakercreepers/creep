package sandbox

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

func TestCheckDockerfileAccepts(t *testing.T) {
	tests := map[string]struct {
		file   string
		images []string
	}{
		"plain":                   {"FROM python:3.12-slim\nCOPY . /app\nRUN pip install --no-index /app\nCMD [\"python\", \"/app/app.py\"]\n", []string{"python:3.12-slim"}},
		"pinned":                  {"FROM docker.io/library/node@sha256:" + strings.Repeat("a", 64) + "\n", []string{"docker.io/library/node@sha256:" + strings.Repeat("a", 64)}},
		"multi-stage":             {"FROM golang:1.27 AS build\nRUN go build -o /x .\nFROM scratch\nCOPY --from=build /x /x\nCOPY --from=0 /x /y\n", []string{"golang:1.27"}},
		"stage case":              {"from golang:1.27 as Build\nfrom Build\ncopy --from=BUILD /x /x\n", []string{"golang:1.27"}},
		"native platform":         {"FROM --platform=$BUILDPLATFORM golang:1.27 AS b\nFROM --platform=${TARGETPLATFORM} alpine:3\n", []string{"alpine:3", "golang:1.27"}},
		"copy from image":         {"FROM scratch\nCOPY --from=busybox:1.37 /bin/sh /sh\n", []string{"busybox:1.37"}},
		"mount from":              {"FROM alpine:3\nRUN --mount=type=bind,from=tools:1,target=/t /t/run\nRUN --mount=type=cache,target=/c true\nRUN --network=none true\n", []string{"alpine:3", "tools:1"}},
		"local add":               {"FROM alpine:3\nADD app.tar.gz /app/\nADD [\"a b\", \"/dst/\"]\nADD --chown=1:1 src $HOME/\n", []string{"alpine:3"}},
		"urls elsewhere":          {"FROM alpine:3\nLABEL org.opencontainers.image.source=https://example.com/x\nRUN echo https://example.com\n", []string{"alpine:3"}},
		"tabs and crlf":           {"FROM\talpine:3\r\nRUN\ttrue\r\n", []string{"alpine:3"}},
		"comment directive later": {"FROM alpine:3\n# syntax=docker/dockerfile:1\n", []string{"alpine:3"}},
		"heredoc":                 {"FROM alpine:3\nRUN <<EOF\necho hi\nEOF\n", []string{"alpine:3"}},
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

// TestCheckDockerfileRefuses: each way a Dockerfile can make the builder
// fetch something outside --network=none, or hide an image from the
// presence check, is refused, however it is spelled.
func TestCheckDockerfileRefuses(t *testing.T) {
	tests := map[string]struct{ file, rule string }{
		"syntax directive":        {"# syntax=docker/dockerfile:1\nFROM alpine:3\n", ruleSyntax},
		"syntax directive spaced": {"#  SYNTAX = evil/frontend\nFROM alpine:3\n", ruleSyntax},
		"syntax after escape":     {"# escape=`\n# syntax=evil/frontend\nFROM alpine:3\n", ruleSyntax},
		"add url":                 {"FROM alpine:3\nADD https://example.com/x /x\n", ruleRemoteAdd},
		"add url lower case":      {"FROM alpine:3\nadd http://example.com/x /x\n", ruleRemoteAdd},
		"add git":                 {"FROM alpine:3\nADD git@github.com:o/r.git /src\n", ruleRemoteAdd},
		"add scp-like":            {"FROM alpine:3\nADD me@host:repo /src\n", ruleRemoteAdd},
		"add variable source":     {"FROM alpine:3\nARG U=https://example.com\nADD $U /x\n", ruleRemoteAdd},
		"add json url":            {"FROM alpine:3\nADD [\"https://example.com/x\", \"/x\"]\n", ruleRemoteAdd},
		"add json escaped url":    {"FROM alpine:3\nADD --chown=1 [\"https\\u003a//example.com/x\", \"/x\"]\n", ruleRemoteAdd},
		"add url continued":       {"FROM alpine:3\nADD \\\n  https://example.com/x \\\n  /x\n", ruleRemoteAdd},
		"add url after comment":   {"FROM alpine:3\nADD \\\n# hidden\n  https://example.com/x /x\n", ruleRemoteAdd},
		"add url backtick escape": {"# escape=`\nFROM alpine:3\nADD `\n  https://example.com/x /x\n", ruleRemoteAdd},
		"variable base":           {"ARG BASE=alpine:3\nFROM $BASE\n", ruleVariableImage},
		"variable base braces":    {"FROM ${BASE:-alpine}\n", ruleVariableImage},
		"variable copy from":      {"FROM alpine:3\nCOPY --from=$IMG /x /x\n", ruleVariableImage},
		"variable mount from":     {"FROM alpine:3\nRUN --mount=type=bind,from=${IMG},target=/t true\n", ruleVariableImage},
		"foreign platform":        {"FROM --platform=linux/s390x alpine:3\n", rulePlatform},
		"run host network":        {"FROM alpine:3\nRUN --network=host wget example.com\n", ruleRunOption},
		"run default network":     {"FROM alpine:3\nRUN --network=default true\n", ruleRunOption},
		"run insecure":            {"FROM alpine:3\nRUN --security=insecure true\n", ruleRunOption},
		"run device":              {"FROM alpine:3\nRUN --device=/dev/kvm true\n", ruleRunOption},
		"flag as image":           {"FROM -x\n", ruleImageName},
		"image with space":        {"FROM alpine 3\n", ruleImageName},
		"no from":                 {"RUN true\n", ruleNoFrom},
		"binary":                  {"FROM alpine:3\x00\n", ruleBinary},
		"too many images":         {manyImages(maxBaseImages + 1), ruleTooManyImages},
	}
	for name, tt := range tests {
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
