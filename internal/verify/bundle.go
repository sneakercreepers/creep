package verify

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"

	"github.com/sneakercreepers/creep/internal/sandbox"
)

// BundleVersion is the reproduction bundle's format. A change that breaks
// reading a stored bundle bumps it (ADR 0020).
const BundleVersion = 1

// MaxBundleBytes bounds a bundle ReadBundle reads: MaxRuns runs of four
// capped requests and responses, escaped, fit far below it.
const MaxBundleBytes = 64 << 20

// ErrBundle marks a bundle ReadBundle refuses, or one NewBundle cannot
// make without a secret in it.
var ErrBundle = errors.New("reproduction bundle")

// Bundle is what `creep reproduce` needs to run a PoC again without the
// model, and what a reader needs to check a verified finding: the PoC,
// every run's requests, responses and timings, the images, the commit
// and the database seed. Every text that came from the model or the app
// went through the caller's Scrub (redact.File) first; one that could not
// be scrubbed is withheld, never kept raw.
type Bundle struct {
	Version  int         `json:"version"`
	Finding  string      `json:"finding"`
	Class    string      `json:"class"`
	Commit   string      `json:"commit"` // the repository's HEAD, "" when unknown
	Images   Images      `json:"images"`
	Seed     Seed        `json:"seed"`
	Port     int         `json:"port"`
	Database bool        `json:"database"`
	PoC      Request     `json:"poc"`
	Rate     Rate        `json:"rate"`
	Runs     []BundleRun `json:"runs"`
}

// Images are the image IDs and pinned references a run used.
type Images struct {
	App      string `json:"app"`      // the built app's local ID, sha256:<hex>
	Runner   string `json:"runner"`   // sandbox.RunnerImage
	Database string `json:"database"` // sandbox.DatabaseImage, "" without a database
}

// Seed is what the run's database was seeded from: the migrations, in the
// order they ran, and the SHA-256 of their contents (SeedDigest).
type Seed struct {
	Migrations []string `json:"migrations"`
	SHA256     string   `json:"sha256"`
}

// BundleRun is one run of the PoC.
type BundleRun struct {
	Outcome Outcome      `json:"outcome"`
	Oracle  string       `json:"oracle"`
	Steps   []BundleStep `json:"steps"`
}

// BundleStep is one request and its answer, scrubbed.
type BundleStep struct {
	Role      string `json:"role"`
	Request   string `json:"request"`
	Response  string `json:"response"`
	Truncated bool   `json:"truncated"`
	ElapsedMS int64  `json:"elapsed_ms"`
	// Withheld means the request or response could not be scrubbed (too
	// large, a line too long, the redactor full), so it is left out.
	Withheld bool `json:"withheld"`
}

// Scrub redacts one text for the bundle: redact.File in production. An
// error withholds the text.
type Scrub func(text []byte) (string, error)

// Meta is what the caller knows about the run beside the PoC.
type Meta struct {
	Finding, Class, Commit string
	Images                 Images
	Seed                   Seed
	Target                 Target
}

var (
	bundleID   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)
	commitHash = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`)
	imageID    = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// ValidBundleID is a finding ID a bundle can be named after: no dot,
// colon or separator, so it is one plain file name on every system.
func ValidBundleID(id string) bool { return bundleID.MatchString(id) }

// NewBundle makes the bundle of one repetition. The PoC goes through
// scrub too, since the model wrote it; if scrubbing breaks it, or it
// cannot be scrubbed, no bundle is made.
func NewBundle(m Meta, p PoC, rep Repetition, scrub Scrub) (Bundle, error) {
	if !p.built || !rep.Rate.Valid() || len(rep.Results) != rep.Rate.Runs || !ValidBundleID(m.Finding) {
		return Bundle{}, fmt.Errorf("%w: not a repetition of a built PoC", ErrBundle)
	}
	poc, err := scrubPoC(p.req, scrub)
	if err != nil {
		return Bundle{}, err
	}
	b := Bundle{
		Version: BundleVersion, Finding: m.Finding, Class: m.Class, Commit: m.Commit,
		Images: m.Images, Seed: m.Seed, Port: m.Target.Port, Database: m.Target.Database,
		PoC: poc, Rate: rep.Rate, Runs: make([]BundleRun, len(rep.Results)),
	}
	for i, res := range rep.Results {
		b.Runs[i] = BundleRun{Outcome: res.Outcome, Oracle: res.Oracle, Steps: scrubSteps(res.Steps, scrub)}
	}
	return b, nil
}

// scrubPoC scrubs the PoC's JSON and reads it back strictly, so the
// bundle holds what reproduce can rebuild, or nothing.
func scrubPoC(req Request, scrub Scrub) (Request, error) {
	raw, err := json.Marshal(req)
	if err != nil {
		return Request{}, fmt.Errorf("%w: encode poc: %w", ErrBundle, err)
	}
	text, err := scrub(raw)
	if err != nil {
		return Request{}, fmt.Errorf("%w: scrub poc: %w", ErrBundle, err)
	}
	var out Request
	if err := decodeStrict([]byte(text), &out); err != nil {
		return Request{}, fmt.Errorf("%w: scrubbed poc: %w", ErrBundle, err)
	}
	return out, nil
}

func scrubSteps(steps []Step, scrub Scrub) []BundleStep {
	out := make([]BundleStep, len(steps))
	for i, s := range steps {
		out[i] = BundleStep{Role: s.Role, Truncated: s.Truncated, ElapsedMS: s.Elapsed.Milliseconds()}
		req, errReq := scrub(s.Request)
		resp, errResp := scrub(s.Response)
		if errReq != nil || errResp != nil {
			out[i].Withheld = true
			continue
		}
		out[i].Request, out[i].Response = req, resp
	}
	return out
}

// ReadBundle reads a bundle strictly: unknown fields, trailing data, an
// unknown version and values a run could not have written are refused.
// The PoC still has to pass Build before it runs.
func ReadBundle(r io.Reader) (Bundle, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxBundleBytes+1))
	if err != nil {
		return Bundle{}, fmt.Errorf("%w: %w", ErrBundle, err)
	}
	if len(data) > MaxBundleBytes {
		return Bundle{}, fmt.Errorf("%w: over %d bytes", ErrBundle, MaxBundleBytes)
	}
	var b Bundle
	if err := decodeStrict(data, &b); err != nil {
		return Bundle{}, fmt.Errorf("%w: %w", ErrBundle, err)
	}
	if err := b.check(); err != nil {
		return Bundle{}, err
	}
	return b, nil
}

// check refuses what NewBundle never writes. Its messages quote nothing:
// the bundle may have been planted.
func (b Bundle) check() error {
	switch {
	case b.Version != BundleVersion:
		return fmt.Errorf("%w: version %d, want %d", ErrBundle, b.Version, BundleVersion)
	case !ValidBundleID(b.Finding):
		return fmt.Errorf("%w: finding ID", ErrBundle)
	case !b.Rate.Valid() || len(b.Runs) != b.Rate.Runs:
		return fmt.Errorf("%w: rate", ErrBundle)
	case b.Commit != "" && !commitHash.MatchString(b.Commit):
		return fmt.Errorf("%w: commit", ErrBundle)
	case !imageID.MatchString(b.Images.App):
		return fmt.Errorf("%w: app image", ErrBundle)
	case verifiedRuns(b.Runs) != b.Rate.Verified:
		return fmt.Errorf("%w: rate does not match the runs", ErrBundle)
	}
	return nil
}

// verifiedRuns counts the runs that verified; -1 for an outcome outside
// the closed set.
func verifiedRuns(runs []BundleRun) int {
	n := 0
	for _, r := range runs {
		switch r.Outcome {
		case Verified:
			n++
		case NotVerified, NoResponse, AuthFailed, NoDatabase:
		default:
			return -1
		}
	}
	return n
}

// SeedDigest is the SHA-256 of the migrations a database was seeded
// from, in order: each path, a NUL, its length and its bytes.
func SeedDigest(migrations []sandbox.Migration) string {
	h := sha256.New()
	for _, m := range migrations {
		fmt.Fprintf(h, "%s\x00%d\x00", m.Path, len(m.SQL))
		h.Write(m.SQL)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func decodeStrict(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing data")
	}
	return nil
}

// WriteBundle writes b as indented JSON.
func WriteBundle(w io.Writer, b Bundle) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(b)
}
