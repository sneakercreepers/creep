package cli

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"

	"github.com/sneakercreepers/creep/internal/calibrate"
	"github.com/sneakercreepers/creep/internal/config"
	"github.com/sneakercreepers/creep/internal/discover"
	"github.com/sneakercreepers/creep/internal/redact"
	"github.com/sneakercreepers/creep/internal/repofile"
	"github.com/sneakercreepers/creep/internal/report"
	"github.com/sneakercreepers/creep/internal/state"
)

// repoScan is the scan's view of the repository after discovery: the
// candidates (IDs, enums and lines only), the paths they index, every file
// not evaluated in full, and what Markdown says about discovery.
type repoScan struct {
	res   discover.Result
	paths []string // indexed by discover.FileID
	gaps  []report.NotEvaluated
	disc  report.Discovery
}

// discoverRepo runs the inventory, the tripwire and model discovery over
// the walked files. An error that stopped the model path (budget,
// run_full, a failed call) is not fatal: the files say why, and the run is
// incomplete. Only a Discoverer that could not start is.
func discoverRepo(ctx context.Context, d discover.Discoverer, files repoFiles) (repoScan, error) {
	marks := &fileMarks{read: d.Read, marks: map[string]repofile.Ignored{}}
	d.Read = marks.readFile
	res, err := d.Run(ctx, files.paths)
	if len(res.Files) != len(files.paths) {
		return repoScan{}, fmt.Errorf("discover: %w", err)
	}
	return discoverRepoResult(res, files, marks.marks), nil
}

// discoverRepoResult builds the scan's view from a discovery Result: the
// walk's gaps, then discovery's, and the Markdown summary.
func discoverRepoResult(res discover.Result, files repoFiles, marks map[string]repofile.Ignored) repoScan {
	gaps := slices.Clone(files.gaps)
	gaps = append(gaps, discoveryGaps(res, files.paths, marks)...)
	return repoScan{res: res, paths: files.paths, gaps: gaps, disc: discoverySummary(res)}
}

// fileMarks records the vendor, generated or minified mark of every file
// discovery reads, so it can be believed afterwards for a file read in
// full with no candidate (ADR 0017), without reading the file again.
type fileMarks struct {
	read  func(string) ([]byte, error)
	marks map[string]repofile.Ignored
}

func (m *fileMarks) readFile(path string) ([]byte, error) {
	data, err := m.read(path)
	if err != nil {
		return nil, err
	}
	if why, err := repofile.IgnoreReason(path, data); err == nil && why != 0 {
		m.marks[path] = why
	}
	return data, nil
}

// readRepoFile reads one repository file for discovery or the reader, at
// most redact.MaxFileBytes: a larger file could not be redacted whole.
func readRepoFile(root *os.Root) func(string) ([]byte, error) {
	return func(path string) ([]byte, error) { return readInRoot(root, path, redact.MaxFileBytes) }
}

// walk lists the repository and says, before any model call, how many
// whole files discovery may send and where (ADR 0017 D1, consent option A).
func (s *session) walk(ctx context.Context, stderr io.Writer) (repoFiles, error) {
	done := s.stats.start(phaseWalk)
	files, err := walkRepo(ctx, s.repo)
	done()
	if err != nil {
		return repoFiles{}, err
	}
	if s.mode() != state.ModeReplay {
		noteWholeFiles(stderr, s.cfg.Model, files.sources())
	}
	return files, nil
}

// noteWholeFiles is the scan-start notice: consent per endpoint carries
// over to discovery's whole-file egress, so the operator is told every
// time. The count is the walk's, made with no model call.
func noteWholeFiles(w io.Writer, m config.Model, files int) {
	target := "endpoint " + m.Endpoint
	if m.Contract == "command" {
		target = "the model command (model.run)"
	}
	fmt.Fprintf(w, "creep scan: discovery sends up to %d whole source files, each redacted, to %s; run creep estimate to see the volume\n",
		files, escapeControl(target))
}

// discover runs discovery at the calibrated tier with the run's seed.
func (s *session) discover(ctx context.Context, tier calibrate.Tier, files repoFiles) (repoScan, error) {
	dtier, err := discoverTier(tier)
	if err != nil {
		return repoScan{}, err
	}
	seed, err := discoverySeed(s.store, s.mode())
	if err != nil {
		return repoScan{}, err
	}
	d := discover.Discoverer{Redactor: s.red, Model: s.model, Tier: dtier, Seed: seed, Read: readRepoFile(s.repo)}
	done := s.stats.start(phaseDiscover)
	defer done()
	return discoverRepo(ctx, d, files)
}

// seedKey names the discovery seed in the run-state cache. The seed is a
// value creep made, not a model reply, but the cache gives it what it
// needs: it is signed with the per-user state secret, so one planted in a
// cloned .creep is a miss and never used (#160), and --replay finds the
// seed of the recorded run, so the requests match byte for byte.
var seedKey = func() state.Key {
	sum := sha256.Sum256([]byte("creep discover canary seed v1"))
	return state.Key{ContentHash: hex.EncodeToString(sum[:]), Model: "creep", PromptVersion: "discover.seed.v1"}
}()

// discoverySeed returns the run's canary seed: 32 bytes from crypto/rand,
// kept only in signed run state. A live run reuses a stored seed, so its
// discovery requests can be served from the cache; --record always makes a
// new one; --replay uses the recorded one, or without a valid one an
// unstored seed, so every discovery request misses and the run ends
// send_failed (exit 4) without a model call.
func discoverySeed(store *state.Store, mode state.Mode) ([32]byte, error) {
	b, err := store.Respond(mode, seedKey, newSeed)
	if err != nil && mode == state.ModeReplay {
		b, err = newSeed()
	}
	if err != nil {
		return [32]byte{}, fmt.Errorf("discovery seed: %w", err)
	}
	if len(b) != 32 || [32]byte(b) == [32]byte{} {
		return [32]byte{}, errors.New("discovery seed: stored seed is not 32 random bytes")
	}
	return [32]byte(b), nil
}

func newSeed() ([]byte, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// storedSeed is the seed estimate measures with: the stored one, so it
// finds the scan's cached requests, or a fresh one when there is none (and
// so no cached discovery request either).
func storedSeed(store *state.Store) ([32]byte, error) {
	if store != nil {
		if b, ok, err := store.Lookup(seedKey); err == nil && ok && len(b) == 32 {
			return [32]byte(b), nil
		}
	}
	b, err := newSeed()
	if err != nil {
		return [32]byte{}, err
	}
	return [32]byte(b), nil
}
