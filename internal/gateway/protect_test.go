package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// pathBreak breaks the gateway path on purpose, in this test only, so each
// protection check is shown to fail when the protection it guards is gone
// (#17). Product code has no such switch.
type pathBreak int

const (
	intact       pathBreak = iota
	rawPayload             // the call carries the file as read, not redact.File output
	unloggedCall           // the call reaches the network without EgressLog.Send
)

// scanProblems scans one file through FileScan, EgressLog.Send and a
// loopback model, then reports every protection it sees broken: a planted
// secret on the wire, in egress.log or in a payload file, and a request the
// endpoint received with no request line whose hash and payload file match.
func scanProblems(t *testing.T, content string, secrets []string, maxFragment int, broken pathBreak) []string {
	t.Helper()
	srv := newModelServer(t, "ok")
	dir := runDir(t)
	l := openLog(t, dir)
	client := srv.client(t)
	scan := FileScan{
		Redactor:         newRedactor(t),
		MaxFragmentBytes: maxFragment,
		Read:             func(string) ([]byte, error) { return []byte(content), nil },
		Send: func(f Fragment) error {
			call := testCall(srv.url("/v1"))
			call.Payload, call.Redactions = []byte(f.Text), f.Redactions
			switch broken {
			case rawPayload:
				call.Payload = []byte(content)
			case unloggedCall:
				_, _, err := post(context.Background(), client.hc, call)
				return err
			}
			_, err := l.Send(context.Background(), client, call)
			return err
		},
	}
	if _, err := scan.Run([]string{"cfg.go"}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	_, bodies := srv.stats()
	problems := planted("on the wire", bodies, secrets)
	problems = append(problems, planted("in the run directory", runFiles(t, dir), secrets)...)
	return append(problems, unlogged(t, dir, bodies)...)
}

// planted reports each secret found in any of blobs.
func planted(where string, blobs [][]byte, secrets []string) []string {
	var out []string
	for _, b := range blobs {
		for _, s := range secrets {
			if bytes.Contains(b, []byte(s)) {
				out = append(out, fmt.Sprintf("planted secret %.12q... %s", s, where))
			}
		}
	}
	return out
}

// runFiles returns egress.log and every payload file of a run.
func runFiles(t *testing.T, dir string) [][]byte {
	t.Helper()
	var out [][]byte
	fsys := os.DirFS(dir)
	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := fs.ReadFile(fsys, path)
		out = append(out, data)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// unlogged reports each body the endpoint received that no egress.log
// request line accounts for, by SHA-256 and by its stored payload file.
func unlogged(t *testing.T, dir string, bodies [][]byte) []string {
	t.Helper()
	logged := map[string]bool{}
	for _, line := range readLines(t, dir) {
		file, _ := line["payload_file"].(string)
		stored, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(file)))
		if line["type"] == "request" && err == nil {
			sum := sha256.Sum256(stored)
			logged[hex.EncodeToString(sum[:])] = line["sha256"] == hex.EncodeToString(sum[:])
		}
	}
	var out []string
	for _, b := range bodies {
		sum := sha256.Sum256(b)
		if !logged[hex.EncodeToString(sum[:])] {
			out = append(out, fmt.Sprintf("%d-byte request sent without an egress.log line", len(b)))
		}
	}
	return out
}

// Protection (#17): a secret never reaches the gateway unredacted, and
// every call is in egress.log. The fuzzer wraps a file of planted secrets in
// arbitrary text and picks the fragment size; CI runs it for a bounded time
// (make protections), make check runs the seed corpus.
func FuzzScanSendsNoSecret(f *testing.F) {
	f.Add("", "", uint64(1), uint16(64))
	f.Add("package x", "func main() {}", uint64(2), uint16(0))
	f.Add("x := `", "`", uint64(3), uint16(4000))
	f.Add("-----BEGIN PRIV"+"ATE KEY-----", "-----END", uint64(4), uint16(128))
	f.Add("password = ", "token: x@y.io", uint64(5), uint16(17))
	f.Add("\xff\xfe", "\x00", uint64(6), uint16(1))
	f.Fuzz(func(t *testing.T, before, after string, seed uint64, frag uint16) {
		if len(before)+len(after) > 4096 {
			t.Skip("keep each run small")
		}
		file, secrets := secretFile(rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15)))
		content := before + "\n" + file + "\n" + after
		if p := scanProblems(t, content, secrets, 16+int(frag)%4096, intact); len(p) != 0 {
			t.Fatalf("protection broken:\n%s", strings.Join(p, "\n"))
		}
	})
}

// Each broken path must trip the check that guards it, so the fuzz target
// above cannot pass vacuously.
func TestScanProtectionsCatchBrokenPath(t *testing.T) {
	tests := []struct {
		name   string
		broken pathBreak
		want   string // substring of a problem; "" means none
	}{
		{"intact path", intact, ""},
		{"unredacted payload", rawPayload, "on the wire"},
		{"unredacted payload is stored", rawPayload, "in the run directory"},
		{"call outside egress.log", unloggedCall, "without an egress.log line"},
	}
	file, secrets := secretFile(rand.New(rand.NewPCG(17, 1)))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := scanProblems(t, file, secrets, 256, tt.broken)
			joined := strings.Join(got, "\n")
			if tt.want == "" && len(got) != 0 || tt.want != "" && !strings.Contains(joined, tt.want) {
				t.Fatalf("problems:\n%s\nwant one containing %q", joined, tt.want)
			}
		})
	}
}
