package config

// Config is the effective configuration. Every leaf field is a key, named by
// the dotted path of its yaml tags (model.endpoint). The desc tags feed
// schema/config.schema.json, which a test keeps in sync with these structs.
type Config struct {
	Model       Model       `yaml:"model"`
	Egress      Egress      `yaml:"egress"`
	Gates       Gates       `yaml:"gates"`
	Budget      Budget      `yaml:"budget"`
	Report      Report      `yaml:"report"`
	Scanners    Scanners    `yaml:"scanners"`
	Sandbox     Sandbox     `yaml:"sandbox"`
	Calibration Calibration `yaml:"calibration"`
	Output      Output      `yaml:"output"`
	Log         Log         `yaml:"log"`
}

type Model struct {
	Contract       string   `yaml:"contract" desc:"How creep talks to the model: an HTTP API (openai, anthropic) or a local command. Cannot be set in the project file."`
	Endpoint       string   `yaml:"endpoint" desc:"Base URL of the model API (http:// or https://). Cannot be set in the project file."`
	Name           string   `yaml:"name" desc:"Model name sent to the endpoint. Cannot be set in the project file."`
	Tier           string   `yaml:"tier" desc:"Unused: the scan takes the tier from calibration. Reserved for a forced-tier option. Cannot be set in the project file."`
	Preset         string   `yaml:"preset" desc:"Name of a model CLI preset built into creep (claude-code, codex, gemini, ollama): sets model.run and contract command. Cannot be set in the project file."`
	Run            string   `yaml:"run" desc:"Command line of a model CLI for contract command: prompt on stdin, JSON on stdout. Split without a shell. Cannot be set in the project file."`
	Env            []string `yaml:"env" desc:"Names of extra environment variables passed to the model command (the rest of the environment is not). Cannot be set in the project file."`
	TimeoutSeconds int      `yaml:"timeout_seconds" desc:"Seconds one model command call may run before it is killed. The project file may only lower it."`
	MaxOutputBytes int      `yaml:"max_output_bytes" desc:"Largest stdout a model command call may print. The project file may only lower it."`
}

type Egress struct {
	Allow []string `yaml:"allow" desc:"Hosts (host or host:port) the gateway may contact. Cannot be set in the project file."`
}

type Gates struct {
	PR      string `yaml:"pr" desc:"Pull request gate: <status>:<severity> or none. Exit 1 when a finding reaches it."`
	Nightly string `yaml:"nightly" desc:"Nightly gate: <status>:<severity> or none."`
}

type Budget struct {
	MaxTokens int `yaml:"max_tokens" desc:"Maximum model tokens per scan. The project file may only lower it."`
	MaxCalls  int `yaml:"max_calls" desc:"Maximum model calls per scan. The project file may only lower it."`
	// MaxSeconds is the scan deadline (#260). It starts after calibration,
	// which reads no repository text, so a hostile repository cannot spend
	// it there.
	MaxSeconds int `yaml:"max_seconds" desc:"Seconds the scan of the repository may run, after calibration: discovery, redaction and model reads. Past it the work left is listed and the run ends incomplete (exit 4). The project file may only lower it."`
}

type Report struct {
	Formats []string `yaml:"formats" desc:"Report files written after a scan. Cannot be set in the project file."`
}

type Scanners struct {
	Enabled []string `yaml:"enabled" desc:"Optional external scanners to run offline when installed (gitleaks, osv-scanner; semgrep is only detected). Cannot be set in the project file."`
}

type Sandbox struct {
	Enabled bool   `yaml:"enabled" desc:"Run proofs of concept in a container (v0.2). The sandbox never has internet access. Cannot be set in the project file."`
	Runtime string `yaml:"runtime" desc:"Container runtime for the sandbox. Cannot be set in the project file."`
}

type Calibration struct {
	CacheDays int `yaml:"cache_days" desc:"Days a model calibration stays valid. The project file may only lower it."`
}

type Output struct {
	Format string `yaml:"format" desc:"Terminal output format (flag --format). Cannot be set in the project file."`
}

type Log struct {
	Level string `yaml:"level" desc:"Log level (flag --log-level)."`
}

// Value ranges for integer keys.
const (
	minCacheDays      = 1
	maxCacheDays      = 365
	minTimeoutSeconds = 1
	maxTimeoutSeconds = 3600
	minScanSeconds    = 1
	maxScanSeconds    = 86400
	minOutputBytes    = 1 << 10
	maxOutputBytes    = 8 << 20
)

// enums lists the allowed values of each enumerated key; for list keys it
// constrains every element. Validation and the schema both read it.
var enums = map[string][]string{
	"model.contract":   {"openai", "anthropic", "command"},
	"model.tier":       {"small", "medium", "large"},
	"report.formats":   {"json", "markdown", "sarif"},
	"scanners.enabled": {"gitleaks", "osv-scanner", "semgrep"},
	"sandbox.runtime":  {"docker", "podman"},
	"output.format":    {"text", "json", "sarif", "markdown"},
	"log.level":        {"debug", "info", "warn", "error"},
}

// projectForbidden keys decide where scanned code is sent; a hostile repo
// could otherwise point them at itself through its creep.yaml.
// model.run and model.env pick the program that receives the code and the
// secrets it gets; model.preset picks a command line, and model.contract
// switches between an HTTP API and that command. model.name picks what the
// operator pays for and, on an aggregator endpoint, which provider reads the
// code (pentest P2). sandbox.* would opt the operator into building and
// running the repository's code (#62). scanners.enabled would run a program
// on the host when it adds a scanner (ADR 0013), and when it removes one a
// class of findings drops out of a run that still reads as complete, so a
// pull request could pass the gate that judges it (#62). model.tier is
// unused today; refusing it now means a forced-tier option, which would pick
// the prompt variant and step caps, can never take it from the repository
// (#250). report.formats and output.format decide what a CI step uploads
// or parses (SARIF, report.json, stdout); a repository dropping them would
// leave that step without its input (#250).
var projectForbidden = map[string]bool{
	"model.contract":   true,
	"model.endpoint":   true,
	"model.name":       true,
	"model.tier":       true,
	"model.run":        true,
	"model.env":        true,
	"model.preset":     true,
	"egress.allow":     true,
	"sandbox.enabled":  true,
	"sandbox.runtime":  true,
	"scanners.enabled": true,
	"report.formats":   true,
	"output.format":    true,
}

// projectLowerOnly keys are the operator's limits on spend and time. The
// project file may lower them but never raise them above what the layers
// before it set (pentest P2, #62). Lowering cannot starve a scan into a
// passing gate: work skipped for budget, a call refused by the gateway
// budget, a timed-out model call and a scan past its deadline each make the
// run incomplete (exit 4).
var projectLowerOnly = []string{
	"budget.max_tokens",
	"budget.max_calls",
	"budget.max_seconds",
	"model.timeout_seconds",
	"model.max_output_bytes",
	"calibration.cache_days",
}

// Enum returns the allowed values of key, or nil when it is not enumerated.
func Enum(key string) []string {
	return append([]string(nil), enums[key]...)
}

// Defaults returns the built-in safe defaults (design.md: CI gates, 30-day
// calibration cache, sandbox off until v0.2).
func Defaults() Config {
	return Config{
		Model:       Model{Contract: "openai", Tier: "medium", Env: []string{}, TimeoutSeconds: 300, MaxOutputBytes: 1 << 20},
		Gates:       Gates{PR: "probable:critical", Nightly: "verified:high"},
		Budget:      Budget{MaxTokens: 2_000_000, MaxCalls: 500, MaxSeconds: 7200},
		Report:      Report{Formats: []string{"json", "markdown", "sarif"}},
		Scanners:    Scanners{Enabled: []string{}},
		Sandbox:     Sandbox{Runtime: "docker"},
		Egress:      Egress{Allow: []string{}},
		Calibration: Calibration{CacheDays: 30},
		Output:      Output{Format: "text"},
		Log:         Log{Level: "info"},
	}
}
