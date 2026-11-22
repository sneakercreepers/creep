package actionscripts

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeGH serves `gh release download` from $FAKE_RELEASE and answers
// `gh attestation verify` with $FAKE_ATTEST, logging each call.
const fakeGH = `echo "$*" >>"$FAKE_LOG"
case "$1 $2" in
  "release download")
    [ "${FAKE_DOWNLOAD:-ok}" = ok ] || exit 1
    dir=""
    while [ $# -gt 0 ]; do
      [ "$1" = --dir ] && dir="$2"
      shift
    done
    cp "$FAKE_RELEASE"/* "$dir"/ ;;
  "attestation verify") exit "${FAKE_ATTEST:-0}" ;;
  *) echo "unexpected gh call" >&2; exit 2 ;;
esac
`

func releaseArchive(t *testing.T, member string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	body := []byte("#!/bin/sh\necho fake creep\n")
	if err := tw.WriteHeader(&tar.Header{Name: member, Mode: 0o755, Size: int64(len(body))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func checksumsFile(archive string, data []byte, mode string) string {
	sum := sha256.Sum256(data)
	good := hex.EncodeToString(sum[:])
	other := strings.Repeat("0", 64) + "  creep_0.2.0_linux_amd64.tar.gz.sbom.json\n"
	switch mode {
	case "bad":
		return strings.Repeat("a", 64) + "  " + archive + "\n" + other
	case "missing":
		return other
	case "duplicate":
		return good + "  " + archive + "\n" + good + "  " + archive + "\n"
	}
	return other + good + "  " + archive + "\n"
}

// Protection (ADR 0023): the downloaded archive runs only after its
// SHA-256 matches checksums.txt and its build provenance verifies against
// the release workflow at the same tag on a GitHub-hosted runner, in that
// order; any failure stops before a binary is extracted. The tag comes from
// the version input or a release-tag Action ref, never from a SHA or branch.
func TestInstallVerifiesBeforeUse(t *testing.T) {
	tests := []struct {
		name        string
		version     string
		actionRef   string
		os, arch    string
		checksums   string
		member      string
		env         map[string]string
		wantCode    int
		want        string
		wantAttest  bool
		wantArchive string
	}{
		{"verified release", "v0.2.0", "", "Linux", "X64", "good", "creep", nil, 0, "checksum and build provenance verified", true, "creep_0.2.0_linux_amd64.tar.gz"},
		{"tag from the Action ref", "", "v0.2.0", "macOS", "ARM64", "good", "creep", nil, 0, "verified", true, "creep_0.2.0_darwin_arm64.tar.gz"},
		{"prerelease tag", "v0.2.0-rc.1", "", "Linux", "ARM64", "good", "creep", nil, 0, "verified", true, "creep_0.2.0-rc.1_linux_arm64.tar.gz"},
		{"checksum mismatch", "v0.2.0", "", "Linux", "X64", "bad", "creep", nil, 1, "checksum mismatch", false, "creep_0.2.0_linux_amd64.tar.gz"},
		{"archive not in checksums", "v0.2.0", "", "Linux", "X64", "missing", "creep", nil, 1, "no single SHA-256", false, "creep_0.2.0_linux_amd64.tar.gz"},
		{"archive listed twice", "v0.2.0", "", "Linux", "X64", "duplicate", "creep", nil, 1, "no single SHA-256", false, "creep_0.2.0_linux_amd64.tar.gz"},
		{"provenance fails", "v0.2.0", "", "Linux", "X64", "good", "creep", map[string]string{"FAKE_ATTEST": "1"}, 1, "did not verify", true, "creep_0.2.0_linux_amd64.tar.gz"},
		{"download fails", "v0.2.0", "", "Linux", "X64", "good", "creep", map[string]string{"FAKE_DOWNLOAD": "no"}, 1, "could not download", false, "creep_0.2.0_linux_amd64.tar.gz"},
		{"archive without creep", "v0.2.0", "", "Linux", "X64", "good", "other", nil, 1, "could not extract", true, "creep_0.2.0_linux_amd64.tar.gz"},
		{"Action pinned by SHA", "", strings.Repeat("ab", 20), "Linux", "X64", "good", "creep", nil, 1, "set the version input", false, ""},
		{"Action on a branch", "", "main", "Linux", "X64", "good", "creep", nil, 1, "set the version input", false, ""},
		{"version with shell text", "v0.2.0;id", "", "Linux", "X64", "good", "creep", nil, 1, "set the version input", false, ""},
		{"version glob", "v0.*", "", "Linux", "X64", "good", "creep", nil, 1, "set the version input", false, ""},
		{"Windows runner", "v0.2.0", "", "Windows", "X64", "good", "creep", nil, 1, "Linux and macOS runners only", false, ""},
		{"32-bit runner", "v0.2.0", "", "Linux", "X86", "good", "creep", nil, 1, "X64 and ARM64 runners only", false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newSandbox(t)
			s.fake("gh", fakeGH)
			release, log := t.TempDir(), filepath.Join(t.TempDir(), "gh.log")
			mustWrite(t, log, "", 0o600)
			archive := tt.wantArchive
			if archive != "" {
				data := releaseArchive(t, tt.member)
				mustWrite(t, filepath.Join(release, archive), string(data), 0o600)
				mustWrite(t, filepath.Join(release, "checksums.txt"), checksumsFile(archive, data, tt.checksums), 0o600)
			}
			s.env = map[string]string{"FAKE_RELEASE": release, "FAKE_LOG": log, "INPUT_VERSION": tt.version,
				"ACTION_REF": tt.actionRef, "RUNNER_OS": tt.os, "RUNNER_ARCH": tt.arch, "GH_TOKEN": "t"}
			for k, v := range tt.env {
				s.env[k] = v
			}
			r := s.run("install.sh")
			wantCode(t, r, tt.wantCode, tt.want)
			calls := mustRead(t, log)
			checkAttestCall(t, calls, tt.wantAttest, tt.version+tt.actionRef)
			checkInstalled(t, r, tt.wantCode == 0)
		})
	}
}

func checkAttestCall(t *testing.T, calls string, want bool, tag string) {
	t.Helper()
	if got := strings.Contains(calls, "attestation verify"); got != want {
		t.Fatalf("attestation verify called: %v, want %v\n%s", got, want, calls)
	}
	if !want {
		return
	}
	for _, arg := range []string{"--repo sneakercreepers/creep", "--signer-workflow sneakercreepers/creep/.github/workflows/release.yml",
		"--source-ref refs/tags/" + tag, "--deny-self-hosted-runners"} {
		if !strings.Contains(calls, arg) {
			t.Errorf("attestation verify lacks %q:\n%s", arg, calls)
		}
	}
}

func checkInstalled(t *testing.T, r result, want bool) {
	t.Helper()
	path, ok := r.outputs["path"]
	if ok != want {
		t.Fatalf("path output %q, want one: %v\n%s", path, want, r.out)
	}
	if want && mustRead(t, path) != "#!/bin/sh\necho fake creep\n" {
		t.Errorf("installed binary is not the archive's creep")
	}
}

// creep-path skips the download and verification, loudly, and only for an
// executable file.
func TestInstallCreepPath(t *testing.T) {
	tests := []struct {
		name     string
		mode     os.FileMode
		wantCode int
		want     string
	}{
		{"executable", 0o755, 0, "unverified local binary"},
		{"not executable", 0o600, 1, "not an executable file"},
		{"missing", 0, 1, "not an executable file"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newSandbox(t)
			s.fake("gh", `echo "gh must not run" >&2; exit 9`)
			path := filepath.Join(t.TempDir(), "creep")
			if tt.mode != 0 {
				mustWrite(t, path, "#!/bin/sh\n", tt.mode)
			}
			s.env = map[string]string{"CREEP_PATH": path, "RUNNER_OS": "Linux", "RUNNER_ARCH": "X64"}
			r := s.run("install.sh")
			wantCode(t, r, tt.wantCode, tt.want)
			if strings.Contains(r.out, "gh must not run") {
				t.Error("creep-path still called gh")
			}
			if (r.outputs["path"] == path) != (tt.wantCode == 0) {
				t.Errorf("path output %q", r.outputs["path"])
			}
		})
	}
}
