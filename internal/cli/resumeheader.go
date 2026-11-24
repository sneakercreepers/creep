package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
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
	{"endpoint", "model endpoint or command (model.endpoint, model.run, model.preset, model.env names or values)"},
	{"model", "model name (model.name)"},
	{"mode", "scan mode (--mode or the CI environment)"},
	{"options", "scan flags (--stability, --changed, --baseline and its entries, --baseline-write, --recalibrate) or installed recipes"},
	{"config", "resolved config (creep config explain)"},
}

// errNoHeader refuses a run started before runs recorded their settings.
var errNoHeader = errors.New("the run records no settings (it was started by a creep without resume), so it cannot be checked; start a new run with creep scan")

// header is the run-state header of this scan's settings: keyed digests
// only (state.Store.HeaderDigest), so the state holds no endpoint, command,
// flag or environment value in clear, and none can be guessed back.
func (s *session) header() (state.Header, error) {
	m := s.cfg.Model
	info := buildinfo.Get()
	prompts := []int{discover.PromptVersion, reader.PromptVersion, calibrate.PromptVersion, verify.PromptVersion}
	fields := map[string][]string{
		"version":  {info.Version, info.Commit},
		"prompts":  {fmt.Sprint(prompts)},
		"contract": {m.Contract},
		"endpoint": endpointParts(m, os.Getenv),
		"model":    {m.Name},
		"mode":     {string(s.gate.mode.Mode)},
		"options":  s.optionsParts(),
		"config":   {configJSON(s.cfg)},
	}
	h := state.Header{}
	for name, parts := range fields {
		d, err := s.store.HeaderDigest(parts...)
		if err != nil {
			return nil, fmt.Errorf("run header: %w", err)
		}
		h[name] = d
	}
	return h, nil
}

// endpointParts are where the model is reached: the endpoint, preset and
// command, and each model.env name with its value (v0.4 release pentest
// P2), since a value can pick the model (GEMINI_MODEL), its settings
// (GEMINI_CLI_HOME) or its host (OLLAMA_HOST). A key in model.env counts
// too, so a rotated key refuses a resume; the header keeps only a keyed
// digest of it.
func endpointParts(m config.Model, getenv func(string) string) []string {
	parts := []string{m.Endpoint, m.Preset, m.Run}
	for _, name := range m.Env {
		parts = append(parts, name, getenv(name))
	}
	return parts
}

// optionsParts are the flags and recipes that change what a scan sends or
// reports. --format and --log-level change neither.
func (s *session) optionsParts() []string {
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
	if s.baseline != nil {
		// The baseline's entries, not only its path: an edited baseline
		// changes the report, so it is refused like any other flag.
		data, err := json.Marshal(s.baseline.file)
		if err != nil {
			data = []byte(err.Error())
		}
		parts = append(parts, "baseline", string(data))
	}
	for _, r := range s.installed {
		parts = append(parts, string(r.Data))
	}
	return parts
}

// configJSON is the resolved config without the output and log settings,
// which change no request and no report.
func configJSON(cfg config.Config) string {
	cfg.Output, cfg.Log = config.Output{}, config.Log{}
	data, err := json.Marshal(cfg)
	if err != nil {
		return "unencodable: " + err.Error()
	}
	return string(data)
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
