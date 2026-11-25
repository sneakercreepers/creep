package releasescripts

import (
	"path/filepath"
	"strings"
	"testing"
)

const (
	tapPut    = "api -X PUT repos/sneakercreepers/homebrew-tap/contents/Casks/creep.rb "
	bucketPut = "api -X PUT repos/sneakercreepers/scoop-bucket/contents/bucket/creep.json "
	noSHA     = "!sha"
)

type failClosedCase struct {
	name       string
	tag, token string
	edit       func(t *testing.T, dist string)
	tap, bkt   string // the release each repository already holds: "" none, "same" this one
	code       int
	want       string
	puts       []string // the PUT calls in order: prefix plus noSHA or the sha they carry
	anyGH      bool     // whether gh may be called at all
}

func editFile(file, old, repl string) func(t *testing.T, dist string) {
	return func(t *testing.T, dist string) { replaceIn(t, filepath.Join(dist, file), old, repl) }
}

var failClosedCases = []failClosedCase{
	{name: "no token", tag: "v0.5.0", want: "were not updated"},
	{name: "prerelease", tag: "v0.5.0-rc1", token: "t", want: "is a prerelease"},
	{name: "not a release tag", tag: "v0.5", token: "t", code: 1, want: "is not a release tag"},
	{name: "first publish", tag: "v0.5.0", token: "t", anyGH: true,
		puts: []string{tapPut + noSHA, bucketPut + noSHA}},
	{name: "update compares versions, not text", tag: "v0.10.0", token: "t", tap: "v0.9.0", bkt: "v0.9.0", anyGH: true,
		puts: []string{tapPut + "sha=sha-creep.rb", bucketPut + "sha=sha-creep.json"}},
	{name: "rerun after partial publish", tag: "v0.5.0", token: "t", tap: "same", anyGH: true,
		want: "already holds v0.5.0", puts: []string{bucketPut + noSHA}},
	{name: "downgrade pushes neither file", tag: "v0.5.0", token: "t", bkt: "v0.10.0", code: 1, anyGH: true,
		want: "refusing a downgrade"},
	{name: "same version, other bytes", tag: "v0.5.0", token: "t", tap: "v0.5.0", code: 1, anyGH: true,
		edit: editFile(caskPath, "postflight_steps", "postflight"), want: "already holds 0.5.0 with other content"},
	{name: "unlisted pin", tag: "v0.5.0", token: "t", code: 1, want: "does not pin exactly",
		edit: editFile("checksums.txt", sum("creep_0.5.0_darwin_amd64.tar.gz"), sum("other"))},
	{name: "sum of another archive", tag: "v0.5.0", token: "t", code: 1, want: "does not pin exactly",
		edit: editFile(scoopPath, sum("creep_0.5.0_windows_amd64.zip"), sum("creep_0.5.0_windows_arm64.zip"))},
	{name: "archive left unpinned", tag: "v0.5.0", token: "t", code: 1, want: "does not pin exactly",
		edit: editFile("checksums.txt", "\n", "\n"+sum("x")+"  creep_0.5.0_linux_riscv64.tar.gz\n")},
	{name: "url of another repository", tag: "v0.5.0", token: "t", code: 1, want: "not an asset of release v0.5.0",
		edit: editFile(caskPath, "sneakercreepers/creep/", "attacker/creep/")},
	{name: "url of another tag", tag: "v0.5.0", token: "t", code: 1, want: "not an asset of release v0.5.0",
		edit: editFile(scoopPath, "/download/v0.5.0/", "/download/v0.4.0/")},
	{name: "version is not the tag", tag: "v0.5.0", token: "t", code: 1, want: "is not at version 0.5.0",
		edit: editFile(caskPath, `version "0.5.0"`, `version "0.5.1"`)},
	{name: "manifest missing", tag: "v0.5.0", token: "t", code: 1, want: "was not generated",
		edit: func(t *testing.T, d string) { mustWrite(t, filepath.Join(d, scoopPath), "") }},
}

// Protection (ADR 0033, v0.5 release review R2, R4, A1): the token step
// publishes nothing without a token, for a prerelease, for a pin that is not
// exactly an archive of this release in checksums.txt, or for a downgrade;
// every refusal comes before any write, so the tap and bucket stay as they were.
func TestPackageReposFailsClosed(t *testing.T) {
	for _, tt := range failClosedCases {
		t.Run(tt.name, func(t *testing.T) {
			dist := t.TempDir()
			writeDist(t, dist, strings.SplitN(tt.tag, "-", 2)[0])
			if tt.edit != nil {
				tt.edit(t, dist)
			}
			env := map[string]string{"PACKAGE_REPOS_TOKEN": tt.token}
			if tt.tap != "" {
				env["FAKE_TAP"] = remote(t, dist, tt.tap, caskPath)
			}
			if tt.bkt != "" {
				env["FAKE_BUCKET"] = remote(t, dist, tt.bkt, scoopPath)
			}
			r := runScript(t, env, tt.tag, dist)
			if r.code != tt.code || !strings.Contains(r.out, tt.want) {
				t.Fatalf("exit %d, want %d with %q:\n%s", r.code, tt.code, tt.want, r.out)
			}
			if !tt.anyGH && r.calls != "" {
				t.Fatalf("gh was called before the checks passed:\n%s", r.calls)
			}
			checkPuts(t, r.calls, tt.puts)
		})
	}
}

// checkPuts fails unless calls holds exactly the PUTs in want, in order.
func checkPuts(t *testing.T, calls string, want []string) {
	t.Helper()
	var puts []string
	for _, line := range strings.Split(calls, "\n") {
		if strings.HasPrefix(line, "api -X PUT ") {
			puts = append(puts, line)
		}
	}
	if len(puts) != len(want) {
		t.Fatalf("%d PUT calls, want %d:\n%s", len(puts), len(want), calls)
	}
	for i, w := range want {
		cut := strings.LastIndex(w, " ") + 1
		prefix, sha := w[:cut], w[cut:]
		switch {
		case !strings.HasPrefix(puts[i], prefix):
			t.Errorf("PUT %d is %q, want %q", i, puts[i], prefix)
		case sha == noSHA && strings.Contains(puts[i], "sha="):
			t.Errorf("PUT %d carries a sha for a new file: %q", i, puts[i])
		case sha != noSHA && !strings.Contains(puts[i], sha):
			t.Errorf("PUT %d lacks %q: %q", i, sha, puts[i])
		}
	}
}

// The PR dry-run checks a snapshot, whose version is not its tag: the
// check-only form takes both, calls no gh and still refuses a URL outside
// the tag's release.
func TestPackageReposCheckPins(t *testing.T) {
	tests := []struct {
		name, tag, version string
		code               int
		want               string
	}{
		{name: "matching tag and version", tag: "v0.5.0", version: "0.5.0", want: "pin the archives"},
		{name: "wrong tag", tag: "v0.4.0", version: "0.5.0", code: 1, want: "not an asset of release v0.4.0"},
		{name: "wrong version", tag: "v0.5.0", version: "0.5.1", code: 1, want: "is not at version 0.5.1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dist := t.TempDir()
			writeDist(t, dist, "v0.5.0")
			r := runScript(t, nil, "--check-pins", tt.tag, tt.version, dist)
			if r.code != tt.code || !strings.Contains(r.out, tt.want) || r.calls != "" {
				t.Fatalf("exit %d, want %d with %q, gh calls %q:\n%s", r.code, tt.code, tt.want, r.calls, r.out)
			}
		})
	}
}
