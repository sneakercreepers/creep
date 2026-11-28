package gatewaytest

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"
)

// Provenance is the header committed next to a replay fixture (#356): who
// answered, at which tier and when. Synthesized fixtures say so; a live
// one names the pinned model, its digest, the recording date and run, and
// Outcomes, what the recorded replies replay to, so a later replay is
// checked against what the model said rather than against the right answer.
type Provenance struct {
	Synthesized bool              `json:"synthesized"`
	Model       string            `json:"model"`
	BaseModel   string            `json:"base_model,omitempty"`
	BaseDigest  string            `json:"base_digest,omitempty"`
	Tier        string            `json:"tier"`
	Recorded    string            `json:"recorded"`
	Run         string            `json:"run,omitempty"`
	Note        string            `json:"note"`
	Outcomes    map[string]string `json:"outcomes,omitempty"`
}

// Environment of a live-record run, read into a live Provenance.
const (
	LiveBaseModelEnv  = "CREEP_LIVE_BASE_MODEL"
	LiveBaseDigestEnv = "CREEP_LIVE_BASE_DIGEST"
	LiveRunEnv        = "CREEP_LIVE_RUN"
)

var datePattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)

// LiveProvenance is the header of a fixture recorded now from s at tier.
func LiveProvenance(s LiveSettings, tier, note string, outcomes map[string]string) Provenance {
	return Provenance{
		Model: s.Model, BaseModel: os.Getenv(LiveBaseModelEnv), BaseDigest: os.Getenv(LiveBaseDigestEnv),
		Tier: tier, Recorded: time.Now().UTC().Format(time.DateOnly), Run: os.Getenv(LiveRunEnv),
		Note: note, Outcomes: outcomes,
	}
}

// SynthesizedProvenance is the header of a fixture synthesized now.
func SynthesizedProvenance(model, tier, note string) Provenance {
	return Provenance{Synthesized: true, Model: model, Tier: tier, Recorded: time.Now().UTC().Format(time.DateOnly), Note: note}
}

// ReadProvenance reads and checks the header at path.
func ReadProvenance(path string) (Provenance, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Provenance{}, fmt.Errorf("provenance: %w", err)
	}
	var p Provenance
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return Provenance{}, fmt.Errorf("provenance %s: %w", path, err)
	}
	return p, p.check()
}

func (p Provenance) check() error {
	switch {
	case p.Model == "" || p.Tier == "" || p.Note == "":
		return errors.New("provenance: model, tier and note must be set")
	case !datePattern.MatchString(p.Recorded):
		return errors.New("provenance: recorded must be a YYYY-MM-DD date")
	case !p.Synthesized && (p.BaseModel == "" || p.BaseDigest == "" || len(p.Outcomes) == 0):
		return errors.New("provenance: a live fixture names its base model, digest and outcomes")
	}
	return nil
}

// WriteProvenance writes p to path, indented, with a trailing newline.
func WriteProvenance(path string, p Provenance) error {
	if err := p.check(); err != nil {
		return err
	}
	out, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(out, '\n'), 0o600)
}

// Fields a committed reply must not carry: provider response metadata
// that identifies a request, a route or an account (#356).
var forbiddenFields = []string{
	"system_fingerprint", "created", "provider", "x-request-id", "request_id",
	"service_tier", "route", "routing", "authorization", "api_key", "x-api-key",
}

// allowedIDs are the placeholder response IDs fixtures use; a provider's
// own ID (chatcmpl-213, msg_01…) is refused.
var allowedIDs = map[string]bool{NormalizedID: true, "chatcmpl-fake": true}

var (
	urlPattern = regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]*://[^\s"\\/]+`)
	keyPattern = regexp.MustCompile(`\b(sk-[A-Za-z0-9_-]{8,}|Bearer\s+[A-Za-z0-9._-]{8,}|AIza[0-9A-Za-z_-]{20,})`)
)

// CheckReplyHygiene returns an error when a recorded reply body holds an
// endpoint (any URL whose host is not under .invalid), something shaped
// like a key, a provider response ID or a routing field.
func CheckReplyHygiene(body []byte) error {
	for _, u := range urlPattern.FindAllString(string(body), -1) {
		host := u[strings.Index(u, "://")+3:]
		if !strings.HasSuffix(strings.ToLower(host), ".invalid") {
			return fmt.Errorf("reply holds an endpoint: %q", u)
		}
	}
	if k := keyPattern.FindString(string(body)); k != "" {
		return errors.New("reply holds something shaped like a key")
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(body, &top); err != nil {
		return fmt.Errorf("reply does not parse: %w", err)
	}
	for _, f := range forbiddenFields {
		if _, ok := top[f]; ok {
			return fmt.Errorf("reply holds the field %q", f)
		}
	}
	return checkID(top["id"])
}

func checkID(raw json.RawMessage) error {
	if raw == nil {
		return nil
	}
	var id string
	if err := json.Unmarshal(raw, &id); err != nil || !allowedIDs[id] {
		return fmt.Errorf("reply holds a provider response id %s", raw)
	}
	return nil
}

// CheckStoreRecording checks the reply held by one internal/state cache
// recording file (a JSON line whose response is base64).
func CheckStoreRecording(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var rec struct {
		Response string `json:"response"`
	}
	if err := json.Unmarshal(data, &rec); err != nil {
		return fmt.Errorf("recording %s: %w", path, err)
	}
	body, err := base64.StdEncoding.DecodeString(rec.Response)
	if err != nil {
		return fmt.Errorf("recording %s: %w", path, err)
	}
	return CheckReplyHygiene(body)
}
