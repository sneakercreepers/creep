package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"

	"github.com/sneakercreepers/creep/internal/buildinfo"
	"github.com/sneakercreepers/creep/internal/calibrate"
	"github.com/sneakercreepers/creep/internal/config"
	"github.com/sneakercreepers/creep/internal/discover"
	"github.com/sneakercreepers/creep/internal/reader"
	"github.com/sneakercreepers/creep/internal/state"
	"github.com/sneakercreepers/creep/internal/verify"
)

// headerFields are the settings a resumed run must share with its original,
// in the order a refusal checks them, each with the name it reports. The
// config digest covers the model fields too, so it comes last and the
// refusal names the narrowest field that differs.
var headerFields = []struct{ key, name string }{
	{"version", "creep version"},
	{"prompts", "prompt versions"},
	{"contract", "model contract (model.contract)"},
	{"endpoint", "model endpoint or command (model.endpoint, model.run, model.preset, model.env)"},
	{"model", "model name (model.name)"},
	{"mode", "scan mode (--mode or the CI environment)"},
	{"options", "scan flags (--stability, --changed, --baseline, --baseline-write, --recalibrate) or installed recipes"},
	{"config", "resolved config (creep config explain)"},
}

// errNoHeader refuses a run started before runs recorded their settings.
var errNoHeader = errors.New("the run records no settings (it was started by a creep without resume), so it cannot be checked; start a new run with creep scan")

// header is the run-state header of this scan's settings: digests only,
// so the state holds no endpoint, command or flag value in clear.
func (s *session) header() state.Header {
	m := s.cfg.Model
	info := buildinfo.Get()
	prompts := []int{discover.PromptVersion, reader.PromptVersion, calibrate.PromptVersion, verify.PromptVersion}
	endpoint := append([]string{m.Endpoint, m.Preset, m.Run}, m.Env...)
	return state.Header{
		"version":  digest(info.Version, info.Commit),
		"prompts":  digest(fmt.Sprint(prompts)),
		"contract": digest(m.Contract),
		"endpoint": digest(endpoint...),
		"model":    digest(m.Name),
		"mode":     digest(string(s.gate.mode.Mode)),
		"options":  s.optionsDigest(),
		"config":   configDigest(s.cfg),
	}
}

// optionsDigest covers the flags and recipes that change what a scan
// sends or reports. --format and --log-level change neither.
func (s *session) optionsDigest() string {
	o := s.opts
	parts := []string{strconv.Itoa(o.stability), strconv.FormatBool(o.recalibrate), o.baseline, strconv.FormatBool(o.baselineWrite)}
	if s.changed != nil {
		changed := make([]string, 0, len(s.changed.paths))
		for p := range s.changed.paths {
			changed = append(changed, p)
		}
		slices.Sort(changed)
		parts = append(append(parts, "changed"), changed...)
	}
	for _, r := range s.installed {
		parts = append(parts, string(r.Data))
	}
	return digest(parts...)
}

// configDigest hashes the resolved config without the output and log
// settings, which change no request and no report.
func configDigest(cfg config.Config) string {
	cfg.Output, cfg.Log = config.Output{}, config.Log{}
	data, err := json.Marshal(cfg)
	if err != nil {
		return digest("unencodable", err.Error())
	}
	return digest(string(data))
}

// digest hashes parts with their lengths, so no two lists collide.
func digest(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		fmt.Fprintf(h, "%d:%s,", len(p), p)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// compareHeader refuses a resume whose settings differ from the run's,
// naming the first field that does.
func compareHeader(recorded, want state.Header) error {
	if recorded == nil {
		return errNoHeader
	}
	for _, f := range headerFields {
		if recorded[f.key] != want[f.key] {
			return &resumeRefusal{field: f.name}
		}
	}
	return nil
}
