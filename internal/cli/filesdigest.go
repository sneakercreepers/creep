package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io/fs"

	"github.com/sneakercreepers/creep/internal/exitcode"
	"github.com/sneakercreepers/creep/internal/state"
)

// filesDigester hashes what a run can read of the walked files, for the
// files step a resume compares (#335).
//
// It reads each file a second time, before discovery reads it (v0.4 review
// A4): the digest must be compared before anything is sent, the tool
// canary included, while discovery sends as it reads and never opens a
// file its name rules out (images, archives) that the sandbox still builds
// from. Keeping every read file in memory until discovery instead would
// hold up to files × redact.MaxFileBytes. The worst case is every file at
// redact.MaxFileBytes: linear, about 190 MB/s on a 2019 laptop
// (BenchmarkFilesDigest). The read is bounded like the scan: it counts
// against budget.max_seconds and stops when the run's context ends.
type filesDigester struct {
	read func(string) ([]byte, error)
	stat func(string) (fs.FileInfo, error)
	// whole are the files whose content is hashed, nil for all of them. A
	// --changed scan hashes only the listed files: the rest are only built
	// by the sandbox, so their size and modification time stand for them
	// and a pull-request scan does not read the whole tree.
	whole map[string]bool
}

func (s *session) filesDigester(scanned repoFiles) filesDigester {
	d := filesDigester{read: readRepoFile(s.repo), stat: s.repo.Lstat}
	if s.changed != nil {
		d.whole = make(map[string]bool, len(scanned.paths))
		for _, p := range scanned.paths {
			d.whole[p] = true
		}
	}
	return d
}

// digest hashes the walked paths, what the scan can read of each (the
// whole file, or only the head of one over the size cap, exactly as
// discovery reads it) and the walk's gaps. It returns the context's cause
// once ctx is done, checked before each file.
func (d filesDigester) digest(ctx context.Context, files repoFiles) (string, error) {
	h := sha256.New()
	for _, path := range files.paths {
		if ctx.Err() != nil {
			return "", context.Cause(ctx)
		}
		d.add(h, path)
	}
	for _, g := range files.gaps {
		fmt.Fprintf(h, "gap %q %s\n", g.Path, g.Reason)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (d filesDigester) add(h hash.Hash, path string) {
	if d.whole != nil && !d.whole[path] {
		info, err := d.stat(path)
		if err != nil {
			fmt.Fprintf(h, "%q unreadable\n", path)
			return
		}
		fmt.Fprintf(h, "%q stat %d %d\n", path, info.Size(), info.ModTime().UnixNano())
		return
	}
	data, err := d.read(path)
	status := "ok"
	switch {
	case errors.Is(err, errFileTooLarge):
		status = "too_large"
	case err != nil:
		status, data = "unreadable", nil
	}
	fmt.Fprintf(h, "%q %s %d\n", path, status, len(data))
	h.Write(data)
}

// errFilesCut is a files digest the deadline or a cancel cut: the run
// cannot be compared, so it stops (exit 4) with nothing sent.
var errFilesCut = errors.New("the scan stopped while creep hashed the repository's files; nothing was sent; the run can be resumed, or start a new run with creep scan")

// stepFiles records the digest of the walked files, or refuses a resumed
// run whose files changed since it recorded theirs. Its time counts against
// budget.max_seconds, which it cannot outlast.
func (s *session) stepFiles(ctx context.Context, all, scanned repoFiles) error {
	ctx, cancel := context.WithTimeoutCause(ctx, s.timeLeft(), errScanDeadline)
	defer cancel()
	start := s.deps.sandbox.clock()
	digest, err := s.filesDigester(scanned).digest(ctx, all)
	s.resume.hashing = max(s.deps.sandbox.clock().Sub(start), 0)
	if err != nil {
		// The hashing time stays spent for a resume of this run.
		if recErr := s.record(state.TimeStep(s.elapsed())); recErr != nil {
			return recErr
		}
		return fmt.Errorf("%w (%w)", errFilesCut, err)
	}
	if recorded, ok := s.resume.finished.Step(state.StepFiles); ok && recorded != digest {
		return &resumeRefusal{field: "file list or a file's content"}
	}
	return s.record(state.StepFiles + digest)
}

// filesStepCode is the exit code of a failed stepFiles: 4 when the run was
// cut, as for any run the deadline or a cancel left incomplete; 2 for a
// refusal or a state error.
func filesStepCode(err error) int {
	if errors.Is(err, errFilesCut) {
		return exitcode.Incomplete
	}
	return exitcode.ConfigError
}
