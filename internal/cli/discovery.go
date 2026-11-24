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
	"github.com/sneakercreepers/creep/internal/gateway"
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
	res, marks, err := runDiscovery(ctx, d, files)
	if err != nil {
		return repoScan{}, err
	}
	return discoverRepoResult(res, files, marks), nil
}

// runDiscovery runs d over the walked files under the scan deadline: past
// it no file is read, and what the deadline left undone is budget
// (deadlineDiscovery). It also returns each read file's mark.
func runDiscovery(ctx context.Context, d discover.Discoverer, files repoFiles) (discover.Result, map[string]repofile.Ignored, error) {
	reads := newDeadlineReads(ctx, d.Read)
	marks := &fileMarks{read: reads.Read, marks: map[string]repofile.Ignored{}}
	d.Read = marks.readFile
	res, err := d.Run(ctx, files.paths)
	if len(res.Files) != len(files.paths) {
		return discover.Result{}, nil, fmt.Errorf("discover: %w", err)
	}
	deadlineDiscovery(ctx, res.Files, files.paths, reads.refused)
	return res, marks.marks, nil
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
		return data, err // an oversized file's head, for discovery to sniff
	}
	if why, err := repofile.IgnoreReason(path, data); err == nil && why != 0 {
		m.marks[path] = why
	}
	return data, nil
}

// wholeFileTarget names where discovery sends: the endpoint, or for a
// model CLI its program, preset and consent key, which egress.log uses.
func wholeFileTarget(m config.Model, cmd *gateway.Command) string {
	if m.Contract != "command" {
		return "endpoint " + m.Endpoint
	}
	if cmd == nil {
		return "the model command (model.run)"
	}
	target := "the model command " + cmd.Program()
	if m.Preset != "" {
		target += " (preset " + m.Preset + ")"
	}
	return target + " at " + cmd.Endpoint()
}

// readRepoFile reads one repository file for discovery or the reader, at
// most redact.MaxFileBytes: a larger file could not be redacted whole.
func readRepoFile(root *os.Root) func(string) ([]byte, error) {
	return func(path string) ([]byte, error) {
		data, err := readInRoot(root, path, redact.MaxFileBytes)
		if !errors.Is(err, errFileTooLarge) {
			return data, err
		}
		// Only the head is read, so discovery can tell source by its
		// shebang or bytes and list it too_large; it is never sent.
		head, headErr := readHeadInRoot(root, path, discover.HeadBytes)
		if headErr != nil {
			head = nil
		}
		return head, fmt.Errorf("%w: %w", errFileTooLarge, redact.ErrFileTooLarge)
	}
}

// walk lists the repository and says, before any model call, how many
// whole files discovery may send and where (ADR 0017 D1, consent option A).
// It returns every walked file, which the sandbox builds from, and the
// files the scan evaluates: with --changed, only the listed ones (#26).
func (s *session) walk(ctx context.Context, stderr io.Writer) (all, scanned repoFiles, err error) {
	done := s.stats.start(phaseWalk)
	all, err = walkRepo(ctx, s.repo)
	done()
	if err != nil {
		return repoFiles{}, repoFiles{}, err
	}
	scanned, s.incremental = s.changed.scope(all)
	if s.mode() != state.ModeReplay {
		noteWholeFiles(stderr, wholeFileTarget(s.cfg.Model, s.link.command), scanned.sources(), s.opts.stability)
	}
	return all, scanned, nil
}

// noteWholeFiles is the scan-start notice: consent per endpoint carries
// over to discovery's whole-file egress, so the operator is told every
// time. The count is the walk's, made with no model call.
func noteWholeFiles(w io.Writer, target string, files, samples int) {
	times := ""
	if samples > 1 {
		times = fmt.Sprintf(" %d times (--stability)", samples)
	}
	fmt.Fprintf(w, "creep scan: discovery sends up to %d whole source files%s, each redacted, to %s; run creep estimate to see the volume\n",
		files, times, escapeControl(target))
}

// discover runs discovery at the calibrated tier with the run's seed.
func (s *session) discover(ctx context.Context, tier calibrate.Tier, files repoFiles) (repoScan, error) {
	dtier, err := discoverTier(tier)
	if err != nil {
		return repoScan{}, err
	}
	seed, err := discoverySeed(s.respond, s.mode())
	if err != nil {
		return repoScan{}, err
	}
	d := discover.Discoverer{Redactor: s.red, Model: s.model, Reruns: s.reruns, Tier: dtier, Seed: seed, Read: readRepoFile(s.repo)}
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
// send_failed (exit 4) without a model call. A resumed run gets the seed
// its finished steps used (session.respond, #335).
func discoverySeed(respond responder, mode state.Mode) ([32]byte, error) {
	b, err := respond(seedKey, newSeed)
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
