package sandbox

import (
	"context"
	"slices"
	"testing"
)

// TestEnginePlatformQuery pins the platform query each engine gets, argv
// for argv, and how its answer is read: Docker's version and Podman's info
// (local, --remote=false) in a fixed Go-template format.
func TestEnginePlatformQuery(t *testing.T) {
	podman := Status{Runtime: Podman, Reachable: true, Rootless: true, Isolation: IsolationRootless, Reason: ReasonOK}
	tests := map[string]struct {
		st       Status
		answer   string
		argv     []string
		platform string
		refused  bool
	}{
		"podman":         {podman, "linux/arm64", []string{"--remote=false", "info", "--format", "{{.Host.OS}}/{{.Host.Arch}}"}, "linux/arm64", false},
		"docker":         {usableDocker(), "linux/amd64", []string{"--host=unix:///run/user/1000/docker.sock", "version", "--format", "{{.Server.Os}}/{{.Server.Arch}}"}, "linux/amd64", false},
		"podman garbage": {podman, "<no value>/<no value>", nil, "", true},
		"podman two":     {podman, "linux/amd64 linux/arm64", nil, "", true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			rec := &recorder{platform: tt.answer}
			s, err := newSandbox(tt.st, testRunID, rec.run)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = s.Close() })
			platform, why, err := s.platform(context.Background())
			if err != nil || platform != tt.platform || (why != nil) != tt.refused {
				t.Fatalf("platform = %q, %+v, %v; want %q, refused %v", platform, why, err, tt.platform, tt.refused)
			}
			if tt.argv != nil && (len(rec.calls) != 1 || !slices.Equal(rec.calls[0], tt.argv)) {
				t.Errorf("argv %q, want %q", rec.calls, tt.argv)
			}
		})
	}
}
