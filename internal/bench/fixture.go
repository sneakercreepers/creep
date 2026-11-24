package bench

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"
)

//go:embed fixtures/published.json
var publishedFixture []byte

// MaxFixtureBytes bounds a fixture file: the published one is well under
// 1 MiB.
const MaxFixtureBytes = 8 << 20

var hashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Fixture is a recorded bench run: the client settings that shaped every
// request body, and one reply per distinct body, keyed by its SHA-256.
type Fixture struct {
	SchemaVersion int          `json:"schema_version"`
	Synthesized   bool         `json:"synthesized"`
	Model         FixtureModel `json:"model"`
	Replies       []Reply      `json:"replies"`
}

// FixtureModel is the client the run used. The bodies depend on every
// field but Endpoint, which is kept so the fixture says where it came
// from; replay never sends anything there.
type FixtureModel struct {
	Contract        string `json:"contract"`
	Endpoint        string `json:"endpoint"`
	Name            string `json:"name"`
	Structured      string `json:"structured"`
	MaxOutputTokens int    `json:"max_output_tokens"`
	Retries         int    `json:"retries"`
}

// Reply is the provider's reply body for one request body.
type Reply struct {
	Request string `json:"request_sha256"`
	Body    string `json:"body"`
}

// Published is the fixture behind docs/bench.
func Published() (Fixture, error) {
	return ParseFixture(bytes.NewReader(publishedFixture))
}

// ParseFixture reads a fixture strictly: version 1, no unknown field, no
// trailing data, sorted unique lowercase hashes, at most MaxFixtureBytes.
func ParseFixture(r io.Reader) (Fixture, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxFixtureBytes+1))
	if err != nil {
		return Fixture{}, fmt.Errorf("bench fixture: %w", err)
	}
	if len(data) > MaxFixtureBytes {
		return Fixture{}, errors.New("bench fixture: over 8 MiB")
	}
	var f Fixture
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return Fixture{}, fmt.Errorf("bench fixture: %w", err)
	}
	if dec.More() {
		return Fixture{}, errors.New("bench fixture: trailing data")
	}
	return f, f.check()
}

func (f Fixture) check() error {
	switch {
	case f.SchemaVersion != 1:
		return errors.New("bench fixture: schema_version must be 1")
	case f.Model.Contract != "openai" && f.Model.Contract != "anthropic":
		return errors.New("bench fixture: model.contract must be openai or anthropic")
	case f.Model.Name == "" || strings.ContainsFunc(f.Model.Name, isControl):
		return errors.New("bench fixture: model.name must be set, with no control character")
	}
	for i, r := range f.Replies {
		if !hashPattern.MatchString(r.Request) {
			return errors.New("bench fixture: request_sha256 must be 64 lowercase hex digits")
		}
		if i > 0 && r.Request <= f.Replies[i-1].Request {
			return errors.New("bench fixture: replies must be sorted by request_sha256, each once")
		}
	}
	return nil
}

func isControl(r rune) bool { return r < 0x20 || r == 0x7f }

// Index returns the replies by request hash.
func (f Fixture) Index() map[string][]byte {
	out := make(map[string][]byte, len(f.Replies))
	for _, r := range f.Replies {
		out[r.Request] = []byte(r.Body)
	}
	return out
}

// RequestHash is the key of a request body.
func RequestHash(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// Recorder collects the replies of a live run. A body asked again gets
// the reply recorded first, so the live run and its replay agree.
type Recorder struct {
	replies map[string][]byte
}

// NewRecorder returns an empty Recorder.
func NewRecorder() *Recorder { return &Recorder{replies: map[string][]byte{}} }

// Lookup returns the reply recorded for body, if any.
func (r *Recorder) Lookup(body []byte) ([]byte, bool) {
	reply, ok := r.replies[RequestHash(body)]
	return reply, ok
}

// Record keeps reply for body unless body already has one. A reply that
// is not UTF-8 is not kept (the file holds it as a JSON string), so its
// replay misses and fails instead of serving a changed body.
func (r *Recorder) Record(body, reply []byte) {
	key := RequestHash(body)
	if _, ok := r.replies[key]; !ok && utf8.Valid(reply) {
		r.replies[key] = slices.Clone(reply)
	}
}

// Fixture returns what was recorded, sorted, under model.
func (r *Recorder) Fixture(model FixtureModel, synthesized bool) Fixture {
	f := Fixture{SchemaVersion: 1, Synthesized: synthesized, Model: model, Replies: []Reply{}}
	for _, key := range slices.Sorted(maps.Keys(r.replies)) {
		f.Replies = append(f.Replies, Reply{Request: key, Body: string(r.replies[key])})
	}
	return f
}

// JSON renders f as the committed file, with a trailing newline.
func (f Fixture) JSON() ([]byte, error) {
	out, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("bench fixture: %w", err)
	}
	return append(out, '\n'), nil
}
