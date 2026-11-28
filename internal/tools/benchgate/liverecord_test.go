package main

import (
	"regexp"
	"strings"
	"testing"
)

var (
	usesLine   = regexp.MustCompile(`(?m)^\s*-?\s*uses:\s*(\S+)`)
	pinnedUses = regexp.MustCompile(`^[\w.-]+/[\w./-]+@[0-9a-f]{40}$`)
	imageLine  = regexp.MustCompile(`(?m)^\s*image:\s*(\S+)`)
	pinnedImg  = regexp.MustCompile(`@sha256:[0-9a-f]{64}$`)
)

// Protection (#356, ADR 0038, threat model B8): the live-record workflow
// records fixtures from the runner's own pinned model and only uploads them
// for review. It holds no secret, pushes nothing, runs with a read-only
// token, never on pull_request_target, and pins every action and image.
func TestLiveRecordWorkflowIsReadOnly(t *testing.T) {
	wf := readRepo(t, ".github", "workflows", "live-record.yml")
	tests := []struct {
		name, needle string
		want         bool
	}{
		{"no permissions at the top", "\npermissions: {}\n", true},
		{"read-only job token", "    permissions:\n      contents: read\n", true},
		{"dispatch trigger", "\n  workflow_dispatch:\n", true},
		{"pull requests that touch it", "\n  pull_request:\n    paths:\n      - .github/workflows/live-record.yml\n", true},
		{"no pull_request_target", "pull_request_target:", false},
		{"no schedule", "schedule:", false},
		{"no push trigger", "\n  push:", false},
		{"no secret", "secrets.", false},
		{"no environment", "environment:", false},
		{"no write permission", ": write", false},
		{"no git push", "git push", false},
		{"no git commit", "git commit", false},
		{"no persisted checkout token", "persist-credentials: false", true},
		{"loopback endpoint only", "CREEP_LIVE_ENDPOINT: http://127.0.0.1:11434/v1\n", true},
		{"no raw bench fixture uploaded", "path: ${{ runner.temp }}/live-recordings/\n", true},
	}
	for _, tt := range tests {
		if got := strings.Contains(wf, tt.needle); got != tt.want {
			t.Errorf("%s: contains %q = %t, want %t", tt.name, tt.needle, got, tt.want)
		}
	}
	if n := strings.Count(wf, "permissions:"); n != 2 {
		t.Errorf("live-record.yml sets permissions %d times, want the top level and the one job", n)
	}
	checkPinned(t, wf)
}

func checkPinned(t *testing.T, wf string) {
	t.Helper()
	uses := usesLine.FindAllStringSubmatch(wf, -1)
	if len(uses) == 0 {
		t.Fatal("live-record.yml uses no action")
	}
	for _, m := range uses {
		if !pinnedUses.MatchString(m[1]) {
			t.Errorf("action %q is not pinned by commit SHA", m[1])
		}
	}
	images := imageLine.FindAllStringSubmatch(wf, -1)
	if len(images) == 0 {
		t.Fatal("live-record.yml runs no service image")
	}
	for _, m := range images {
		if !pinnedImg.MatchString(m[1]) {
			t.Errorf("image %q is not pinned by digest", m[1])
		}
	}
}

// The recordings and the nightly bench run the same pinned model, so a
// re-pin of one is a re-pin of the other (ADR 0038).
func TestLiveRecordPinsTheBenchModel(t *testing.T) {
	live := readRepo(t, ".github", "workflows", "live-record.yml")
	bench := readRepo(t, ".github", "workflows", "bench.yml")
	for _, re := range []*regexp.Regexp{digestLine, modelLine} {
		l, b := re.FindStringSubmatch(live), re.FindStringSubmatch(bench)
		if l == nil || b == nil || l[1] != b[1] {
			t.Errorf("%s: live-record.yml %v, bench.yml %v", re, l, b)
		}
	}
	digest := digestLine.FindStringSubmatch(live)
	if digest != nil && !strings.Contains(live, "CREEP_LIVE_BASE_DIGEST: "+digest[1]+"\n") {
		t.Error("the recordings' header digest is not the pinned digest")
	}
}
