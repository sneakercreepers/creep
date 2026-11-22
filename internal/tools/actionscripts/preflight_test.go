package actionscripts

import (
	"strings"
	"testing"
)

// Protection (ADR 0023): the Action runs only on events that check out the
// base repository's own code or a pull request without the base
// repository's secrets, and refuses any model key on a pull request from a
// fork, whichever variable carries it.
func TestPreflightPolicy(t *testing.T) {
	const repo = "owner/app"
	tests := []struct {
		name     string
		env      map[string]string
		wantCode int
		wantFork string // "" when nothing is written
		want     string
	}{
		{"push", map[string]string{"EVENT_NAME": "push", "INPUT_API_KEY": "k"}, 0, "false", ""},
		{"schedule", map[string]string{"EVENT_NAME": "schedule", "CREEP_API_KEY": "k"}, 0, "false", ""},
		{"workflow_dispatch", map[string]string{"EVENT_NAME": "workflow_dispatch"}, 0, "false", ""},
		{"merge_group", map[string]string{"EVENT_NAME": "merge_group"}, 0, "false", ""},
		{"same-repository pull request with a key", map[string]string{"EVENT_NAME": "pull_request", "HEAD_REPO": repo, "INPUT_API_KEY": "k"}, 0, "false", ""},
		{"fork pull request without a key", map[string]string{"EVENT_NAME": "pull_request", "HEAD_REPO": "other/app"}, 0, "true", "comment is skipped"},
		{"fork pull request with the api-key input", map[string]string{"EVENT_NAME": "pull_request", "HEAD_REPO": "other/app", "INPUT_API_KEY": "k"}, 1, "", "refusing to run"},
		{"fork pull request with CREEP_API_KEY", map[string]string{"EVENT_NAME": "pull_request", "HEAD_REPO": "other/app", "CREEP_API_KEY": "k"}, 1, "", "refusing to run"},
		{"fork pull request with ANTHROPIC_API_KEY", map[string]string{"EVENT_NAME": "pull_request", "HEAD_REPO": "other/app", "ANTHROPIC_API_KEY": "k"}, 1, "", "refusing to run"},
		{"fork pull request with CLAUDE_CODE_OAUTH_TOKEN", map[string]string{"EVENT_NAME": "pull_request", "HEAD_REPO": "other/app", "CLAUDE_CODE_OAUTH_TOKEN": "k"}, 1, "", "refusing to run"},
		{"fork pull request with OPENAI_API_KEY", map[string]string{"EVENT_NAME": "pull_request", "HEAD_REPO": "other/app", "OPENAI_API_KEY": "k"}, 1, "", "refusing to run"},
		{"deleted fork counts as a fork", map[string]string{"EVENT_NAME": "pull_request", "INPUT_API_KEY": "k"}, 1, "", "refusing to run"},
		{"look-alike repository name", map[string]string{"EVENT_NAME": "pull_request", "HEAD_REPO": repo + "-fork", "INPUT_API_KEY": "k"}, 1, "", "refusing to run"},
		{"pull_request_target", map[string]string{"EVENT_NAME": "pull_request_target", "HEAD_REPO": repo}, 1, "", "event pull_request_target is not supported"},
		{"workflow_run", map[string]string{"EVENT_NAME": "workflow_run"}, 1, "", "is not supported"},
		{"issue_comment", map[string]string{"EVENT_NAME": "issue_comment"}, 1, "", "is not supported"},
		{"no event", map[string]string{}, 1, "", "event (unprintable) is not supported"},
		{"event name with a workflow command", map[string]string{"EVENT_NAME": "x\n::warning::y"}, 1, "", "event (unprintable) is not supported"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newSandbox(t)
			s.env = tt.env
			s.env["REPOSITORY"] = repo
			r := s.run("preflight.sh")
			wantCode(t, r, tt.wantCode, tt.want)
			if r.outputs["fork"] != tt.wantFork {
				t.Errorf("fork=%q, want %q", r.outputs["fork"], tt.wantFork)
			}
			if strings.Contains(r.out, "::warning::y") {
				t.Errorf("event name reached a workflow command:\n%s", r.out)
			}
		})
	}
}
