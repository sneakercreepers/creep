package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"regexp"
	"strings"

	"github.com/sneakercreepers/creep/internal/verify"
)

// bundleDir holds one reproduction bundle per verified finding in .creep,
// as <finding ID>.json (#25).
const bundleDir = "bundles"

// writeBundle makes the finding's bundle with scrub (the scan's
// redact.File) and writes it through root, the state store's checked
// handle, never through a planted link.
func writeBundle(root *os.Root, meta verify.Meta, p verify.PoC, rep verify.Repetition, scrub verify.Scrub) error {
	b, err := verify.NewBundle(meta, p, rep, scrub)
	if err != nil {
		return err
	}
	var data bytes.Buffer
	if err := verify.WriteBundle(&data, b); err != nil {
		return err
	}
	if err := root.Mkdir(bundleDir, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("bundle directory: %w", err)
	}
	return replaceInRoot(root, bundleName(meta.Finding), data.Bytes())
}

func bundleName(id string) string { return path.Join(bundleDir, id+".json") }

// removeBundles deletes the last run's bundles with the stale reports, so
// a bundle the repository committed under .creep, or one an earlier scan
// left, never passes for this run's.
func removeBundles(root *os.Root) error {
	if err := root.RemoveAll(bundleDir); err != nil {
		return fmt.Errorf("remove stale %s: %w", bundleDir, err)
	}
	return nil
}

// readBundle reads the last scan's bundle of one finding through .creep's
// own checks, as creep why reads the report.
func readBundle(id string) (verify.Bundle, error) {
	if !verify.ValidBundleID(id) {
		return verify.Bundle{}, fmt.Errorf("invalid finding ID %q", id)
	}
	root, err := openStateDir()
	if err != nil {
		return verify.Bundle{}, err
	}
	defer root.Close()
	data, err := readInRoot(root, bundleName(id), verify.MaxBundleBytes)
	if err != nil {
		return verify.Bundle{}, fmt.Errorf("no reproduction bundle for %s (only a verified finding of the last scan has one): %w", id, err)
	}
	b, err := verify.ReadBundle(bytes.NewReader(data))
	if err != nil {
		return verify.Bundle{}, err
	}
	if b.Finding != id {
		return verify.Bundle{}, fmt.Errorf("%s holds another finding's bundle: %w", bundleName(id), verify.ErrBundle)
	}
	return b, nil
}

// Bounds on what headCommit reads from .git.
const (
	gitRefBytes    = 4 << 10
	packedRefBytes = 4 << 20
)

var (
	commitID = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`)
	refName  = regexp.MustCompile(`^refs/[A-Za-z0-9._/-]{1,200}$`)
)

// headCommit is the repository's HEAD commit for the bundle, read from
// .git without running git: a detached HEAD, a loose ref or a packed one.
// "" when it cannot tell; it never fails the scan.
func headCommit(repo *os.Root) string {
	head, err := readInRoot(repo, ".git/HEAD", gitRefBytes)
	if err != nil {
		return ""
	}
	line := strings.TrimSpace(string(head))
	if commitID.MatchString(line) {
		return line
	}
	ref, ok := strings.CutPrefix(line, "ref: ")
	if !ok || !refName.MatchString(ref) || strings.Contains(ref, "..") {
		return ""
	}
	if loose, err := readInRoot(repo, ".git/"+ref, gitRefBytes); err == nil {
		if id := strings.TrimSpace(string(loose)); commitID.MatchString(id) {
			return id
		}
	}
	return packedRef(repo, ref)
}

func packedRef(repo *os.Root, ref string) string {
	packed, err := readInRoot(repo, ".git/packed-refs", packedRefBytes)
	if err != nil {
		return ""
	}
	for line := range strings.Lines(string(packed)) {
		id, name, ok := strings.Cut(strings.TrimSpace(line), " ")
		if ok && name == ref && commitID.MatchString(id) {
			return id
		}
	}
	return ""
}
