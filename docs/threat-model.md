# Threat model

What `creep` protects, from whom, where the trust boundaries are, and which control and test holds each one. It describes the code on `main` (v0.1 in progress), not the roadmap: anything not built yet is marked **planned** with its issue, and §7 lists the requirements it must meet before it ships.

Review it:

- for every pull request that crosses a trust boundary (§2). The PR template has the checklist; CODEOWNERS covers the paths;
- in the release pentest and the per-version architecture review ([ADR 0004](adr/0004-pentester-per-release.md), [ADR 0005](adr/0005-auditor-architecture-review.md));
- in full at least once per major version.

Architecture and package responsibilities: [architecture.md](architecture.md). Package list: [map.md](map.md). Reporting a vulnerability: [SECURITY.md](../SECURITY.md).

## 1. Assets

| ID | Asset | Why it matters |
|---|---|---|
| A1 | Source code of the scanned repository | It leaves the machine only as redacted fragments, only to an endpoint the user allowlisted and consented to |
| A2 | Secrets and personal data inside that code | They must never reach a model endpoint unredacted |
| A3 | The model API key (`CREEP_API_KEY`) | Spend and account access |
| A4 | The user's machine | `creep` reads hostile input; it must never run it or let it choose what `creep` runs |
| A5 | Integrity of the result: findings, coverage, exit code | CI gates trust them; a run that missed work must never read as clean |
| A6 | The audit trail: `egress.log` and `payloads/` | The user's record of exactly what left the machine and where |
| A7 | Trust state outside the repository: the state secret (`<user config dir>/creep/state.key`), the consent store, the calibration cache | They decide which recordings, runs, consents and tiers are believed |
| A8 | The `creep` source, build and release | A compromised `creep` compromises every user |

## 2. Trust boundaries

```
              operator-trusted                 │            untrusted
                                               │
 flags · user file · --config · CREEP_POLICY   │   scanned repository: code, file names,
 CREEP_API_KEY · consent store · state.key ────┼──► creep.yaml, a planted .creep/      (TB1)
                                               │
 ┌──────────────────────── creep process ──────┼─────────────────────────────────────┐
 │ static ──► WASM parser (wazero guest)  (TB2)│                                     │
 │   │ IDs and enums only                      │                                     │
 │   ▼                                         │                                     │
 │ planner ◄── Signal (IDs, enums, numbers) ── reader ◄── redacted slices            │
 │  (no text)                       (TB3)      │  │                                  │
 │                                             │  ▼                                  │
 │ report ◄──────────────────────────── models ◄── gateway ◄── redact               │
 └──────┬──────────────────────────────────────┼──────┬──────────────────────────────┘
        ▼ (TB6)                                │      ▼ HTTPS, allowlisted (TB4)
  .creep/report.* · terminal · CI              │   model endpoint: its replies are
  · GitHub code scanning                       │   untrusted (TB5)
```

| ID | Boundary | What crosses it | Controls |
|---|---|---|---|
| TB1 | Scanned repository → `creep` | File contents and names, `creep.yaml`, whatever sits in `.creep/` | Read through `os.Root`, regular files only, size caps, no FIFO blocking; project config cannot choose where code goes, grant consent or loosen gates; state is believed only with a valid HMAC from a secret outside every repository |
| TB2 | Hostile source → parser | Bytes parsed by tree-sitter grammars | Grammars run as WebAssembly in wazero with no file system, network, clock or environment, a memory cap (256 MiB), a node cap (2^20), a 30 s deadline and host-side validation of every record; grammars pinned by `SHA256SUMS` ([ADR 0008](adr/0008-wazero-tree-sitter.md)) |
| TB3 | Code-reading step → deciding step | Reader verdicts to the planner; static facts to the planner | The planner receives only IDs, enums, booleans and numbers; `planner` and `reader` never import each other (layer table, `make budget`); types checked by reflection |
| TB4 | `creep` → network | Redacted payloads to model endpoints | `internal/gateway` is the only package that can import networking; redaction first; per-origin consent; allowlist before DNS; TLS except loopback; DNS pinning; non-public addresses refused; proxy variables ignored; no redirects on send; token and call budget; write-ahead `egress.log` |
| TB5 | Model reply → `creep` | JSON from the endpoint | Size cap, strict decoding into closed structs (unknown, duplicate and case-variant keys refused), bounded retries, never executed, never shown to the planner as text |
| TB6 | `creep` → its outputs | Reports, terminal output, exit code | Repository and log strings escaped in Markdown and on the terminal; SARIF URIs percent-encoded; incomplete runs exit 4, never 0; reports written by remove-then-exclusive-create inside `.creep` |
| TB7 | Contributors and dependencies → `creep` | Pull requests, Go modules, CI actions, releases | Dependency allowlist with ADRs, import and reach rules, pinned workflows, CODEOWNERS, rulesets, the agent loop |
| TB8 | `creep` → other programs | Model CLIs (#6, contract command); gitleaks and osv-scanner (#221, ADR 0013); container runtime (**planned**, v0.2) | Only `internal/gateway` (model CLIs) and `internal/scanrun` (scanners) start programs (`make budget`). Model CLIs run only through `EgressLog.Exec` after consent, budget and the write-ahead `egress.log` line ([ADR 0014](adr/0014-command-model-through-gateway.md)): argv split without a shell; final path outside the repository and working directory (links, junctions and `\\?\` resolved, compared by file identity), no device or UNC path; minimal environment; empty temp working directory; timeout and stdout cap; process group killed on Unix; tool canary. Scanners: the final path outside the repository and working directory (links and junctions followed, compared by file identity), only an `.exe` on Windows, fixed offline arguments, no shell, creep's own tool config, empty `PATH`, fresh `HOME`/`TMP`/cwd, proxies at a closed loopback port, no keys, timeout and output caps; the project file cannot enable a scanner. §7 lists what the other parts need |

## 3. Attackers

| Attacker | Controls | Wants |
|---|---|---|
| **Malicious repository** (the default case: `creep` is run on code nobody vetted, including pull requests) | Every byte of the tree: code, comments, file and directory names, links, `creep.yaml`, a pre-made `.creep/` | Run code on the scanning machine; exfiltrate secrets or code to its own endpoint; steer the planner; hide a vulnerability; make an incomplete scan pass a CI gate; inject markup or terminal sequences into reports; exhaust CPU or memory |
| **Malicious or compromised model endpoint** (also: a model fooled by repository text) | Every reply byte, status code and redirect | Get output executed; reach the planner; inject into reports; burn the budget; get code re-sent elsewhere; lie about vulnerabilities |
| **Network attacker** | DNS answers, routing, a proxy, plain HTTP | Read or alter traffic; make `creep` reach internal services (SSRF, cloud metadata) |
| **Malicious recipe or preset** (presets: §4.2a C6; recipes **planned**, v0.3) | A data file merged into creep (presets are embedded) or installed by the user (recipes) | Run commands; loosen redaction or gates; point at another endpoint |
| **Local user** on the same machine (another account) | Shared directories, links, file permissions | Read `egress.log`, payloads or state; plant consent or state |
| **Malicious contributor or upstream** | A pull request, a dependency, a CI action | Ship a backdoor, add a network or exec path, weaken the review loop |

## 4. Threats and mitigations

Tests are in the package named, as `file:Test`; "budget" means `make budget` (`internal/tools/budget`), which CI runs as a required job.

### 4.1 Malicious repository

| ID | Threat | Mitigation | Held by |
|---|---|---|---|
| R1 | Prompt injection in code steers which hypotheses are checked | The planner gets IDs, enums and booleans only, copied by the CLI through explicit switches; the static graph can hold no text | `planner/text_test.go:TestInputCarriesNoText`, `TestBuildTakesOnlyInput`; `static/planner_text_test.go:TestPlannerOutputHasNoRepoStrings`, `jsplanner_text_test.go:TestPlannerOutputHasNoRepoStringsJS`; `cli/plannermap_test.go`; budget layer table; `cli/protect_test.go:TestHolisticReplayProtections` (planner input of a real scan holds no text) |
| R2 | Injected text poses as instructions or as a fake code line in the reader prompt | System prompt is fixed data; the `HYPOTHESIS` line is built from enums and integers; every repository line sits behind its number with control, format, separator and bidi runes escaped | `reader/render_test.go:TestHostileCodeStaysData`, `TestEscapeLine` |
| R3 | Injection fools the reader into "not vulnerable" | **Residual.** The worst case is a missed finding (false negative), never execution or egress. Limits: the answer must fit a closed schema and cite only lines it was shown; calibration measures the model per class; the report says what was evaluated | `reader/output_test.go:TestAnswerRejectsHostileOutput`; `reader/signal_test.go:TestProject` |
| R4 | `creep.yaml` sends code to the attacker's endpoint or program, or grants consent | The project file cannot set `model.endpoint`, `egress.allow`, `model.run` or `model.env`; consent is not a config key | `config/protections_test.go:TestProjectCannotChooseWhereCodeGoes`, `TestFixedProtectionsHaveNoKeys`; `config/command_test.go:TestProjectCannotChooseModelCommand`; `cli/modelcmd_test.go:TestProjectFileCannotSetModelCommand`; `gateway/consent_test.go:TestCINeverPrompts` |
| R5 | `creep.yaml` loosens the gate that judges its own pull request | A project gate looser than the built-in default or policy limit is rejected | `config/protections_test.go:TestProjectCannotLoosenBuiltInGates`, `TestProjectLooseGateRejectedEvenIfFlagOverrides` |
| R6 | A committed `.creep/` plants recorded model replies, a "complete" run or a report | Every state line carries an HMAC keyed by the per-user secret outside every repository; unauthenticated cache entries are misses, runs fail closed; `creep why` reads the report strictly and prints it escaped; calibrations live in the user cache, signed the same way | `state/trust_test.go:TestPlantedCacheEntryNeverServed`, `TestPlantedRunLogNeverTrusted`, `TestRunLinesBoundToTheirRun`; `cli/why_test.go:TestWhyDistrustsTheReportFile`; `calibrate/cache_test.go:TestUntrustedCacheRecalibrates` |
| R7 | `.creep` or a file in it is a link, so `creep` writes or reads elsewhere | The state directory must be a real directory not writable by others and is used through `os.Root`; reports are removed and created with `O_EXCL` inside it | `state/run_test.go:TestOpenRefusesUnsafeDir`; `state/corrupt_test.go:TestRunLogSymlinkRefused`, `TestRunPathNotRegular`; `state/trust_test.go:TestRunsDirMustBeDirectory`; `cli/scanout.go` (`replaceInRoot`) |
| R8 | Links, FIFOs or devices in the tree read files outside the repository or hang the scan | The walk reads through `os.Root`, takes regular files only and lists every other entry as `not_regular`; opens never block on a FIFO | `cli/walk_test.go:TestWalkListsLinks`; `cli/fifo_unix_test.go:TestConfigRejectsFIFO` |
| R9 | Code hides from the scan: a nested `.git` or `.creep`, a vendor or generated marker, an unsupported language, a syntax error, an odd name | Only the root `.git` and `.creep` are skipped; every other file not evaluated in full is listed with a closed reason and makes the run incomplete (exit 4), except vendor code and tier S low-risk skips, which stay listed | `cli/walk_test.go:TestWalkSkipsOnlyRootStateDirs`, `TestScanListsRefusedName`; `cli/scan_test.go:TestScanExitCodes`, `TestScanListsUngrammaredSource`; `static/ignore_test.go:TestIgnoredFileIsListedNotExtracted` |
| R10 | A secret in the code reaches the model | Each file is redacted whole by `redact.File` before anything cuts it; the gateway and the reader fragment only that output; a file redaction rejects is never sent | `gateway/scan_test.go:TestScanSendsOnlyRedactedFragments`, `TestScanSkipsFilesRedactRejects`; `reader/slice_test.go:TestBuildMasksSecretsInSlices`; `redact/file_leak_test.go:TestFileHidesSecretsAcrossChunks`; `gateway/protect_test.go:FuzzScanSendsNoSecret` (bounded fuzz in CI `protections`), `TestScanProtectionsCatchBrokenPath`; `cli/protect_test.go:TestHolisticReplayProtections` |
| R11 | Repository text forges a redaction marker, or floods the run so later secrets go unmasked | Marker-like text is escaped; one file may add at most its share of the run's values; a full run returns `ErrRunFull` and the scan stops incomplete | `redact/redactor_test.go:TestEscapeForgedMarkers`; `redact/share_test.go:TestCraftedFileCannotFillRun`; `gateway/scan_test.go:TestScanStopsWhenRunFull`; `reader/slice_test.go:TestBuildStopsWhenRunFull` |
| R12 | A crafted file exploits the parser or exhausts CPU and memory | Sandboxed WASM parser with caps (TB2); RE2 regexps are linear; redaction, static walks and slices are bounded per file and per run | `static/grammar_test.go:TestEmbeddedGrammarsMatchSums`, `TestGrammarImportsOnlyAllowedWASI`; `static/parser_test.go:TestParseLimits`, `TestParseRejects`; `static/jslimits_test.go`; `redact/perf_test.go:TestRedactLargeInputIsBounded` |
| R13 | File names inject Markdown, links or terminal escapes into reports or output | Repository strings are printed as escaped code spans; terminal output escapes control runes; SARIF URIs are percent-encoded | `report/escape_test.go:TestRenderedOutputIsInert`, `TestURIPath`; `cli/scan_test.go:TestScanListsFilesEscaped` |
| R14 | The scanned code gets executed | Nothing in the product starts a process except the operator's model CLI (`internal/gateway`, ADR 0014: final path outside the repository and working directory, empty temp cwd; `gateway/command_test.go`, `command_windows_test.go`, `command_unix_test.go`) and `internal/scanrun`, which refuses any binary whose final path is in the repository or the working directory, runs no `.bat`/`.cmd`, and never takes a scanner choice from the project file (ADR 0013; `scanrun/run_test.go`, `run_windows_test.go`, `static/scanners_test.go`, `config/scanners_test.go`); the deliberately vulnerable `testdata/apps` are never named by a Makefile, workflow, script or process-starting Go code | budget exec rules (`imports.go`, `procs.go`); `tools/testapps/apps_test.go:TestNothingExecutesApps` |
| R15 | An optional scanner reaches the network, leaks a secret or hides results | Offline flags only (gitleaks `--no-git`, osv-scanner `--offline` with the operator's local database, semgrep not run); proxies at a closed loopback port and an empty `PATH` as backstop; gitleaks `--redact` and only file, line and IDs decoded, rule and advisory IDs hashed; creep's own gitleaks and osv-scanner config, so the repository's `.gitleaks.toml` and `osv-scanner.toml` are ignored; gitleaks is not started (`failed`, run incomplete) when the repository root holds a `.gitleaksignore`, which gitleaks always reads; osv-scanner runs with `--no-ignore` and only against a database that holds an ecosystem `all.zip`; on timeout the process group is killed (Unix); any failure makes the run incomplete. **Residual:** a tool could open raw sockets despite its flags; inline `gitleaks:allow` comments still hide single findings; a database missing the repository's ecosystem matches nothing for it; on Windows a helper a scanner started could outlive a timeout; the binary could be swapped between the check and the start by someone who can write to the operator's own `PATH` directories | `scanrun/run_test.go:TestRun`, `TestRunRefusesWithoutStarting`, `TestParseRejectsHostileReports`; `scanrun/proc_unix_test.go:TestTimeoutKillsProcessTree`; `cli/scanners_run_test.go` |

### 4.2 Malicious model endpoint

| ID | Threat | Mitigation | Held by |
|---|---|---|---|
| M1 | A reply gets executed | Replies decode into closed structs after a size cap; unknown, duplicate and case-variant keys are refused; the only exec path (`internal/scanrun`) has fixed arguments and never takes model output | `models/strictkeys_test.go:TestDecodeOutputStrictKeys`; `models/request_test.go:TestDecodeOutput`; budget exec rules |
| M2 | A reply's text reaches the planner | Only `reader.Signal` (IDs, enums, numbers) reaches the planner | `reader/signal_test.go:TestSignalCarriesNoText`, `TestProjectRevalidates` |
| M3 | Reply text flows into the retry prompt, errors or reports | Retry reasons are creep's fixed text; evidence is line numbers; report strings are escaped | `models/injection_test.go:TestReplyKeysNeverReachReason`; `models/complete_test.go:TestRetryPromptCarriesReasonNotModelText` |
| M4 | Endless replies or retries burn money | `max_tokens` per call, bounded retries, run and per-endpoint token and call budgets reserved before sending, AIMD concurrency | `gateway/budget_test.go:TestSendRefusesOverBudget`, `TestConcurrentSendsStayInBudget`; `models/complete_test.go:TestCompleteDoesNotRetryEndpointFailures` |
| M5 | A redirect makes `creep` re-send the payload to another host | `Send` follows no redirects; the client allows only same-origin ones; a transport retry never replays the body | `gateway/send_safety_test.go:TestRedirectNotFollowed`, `TestTransportRetryDoesNotResend`; `gateway/redirect_test.go` |
| M6 | Errors leak the key or URL credentials | The key travels only in a header the gateway never logs; errors strip userinfo and query | `models/egress_test.go:TestKeyNeverReachesEgressLog`; `models/key_test.go:TestKeyNeverPrints`; `gateway/send_safety_test.go:TestErrorsHideCredentials` |
| M7 | The model lies, so findings are missed or invented | **Residual.** Calibration on generated tasks gives a tier per class; reader findings are at most `probable` in v0.1 (`verified` needs the v0.2 sandbox); every unevaluated sink is listed | `calibrate/run_test.go`, `tier_test.go`; `report/report_test.go:TestNotEvaluatedListedEverywhere` |

### 4.2a Model CLI (contract command)

| ID | Threat | Mitigation | Held by |
|---|---|---|---|
| C1 | The configured command line runs a shell, a pipe or a planted program | Split without a shell; shell syntax outside quotes is refused; the program comes from an absolute `PATH` entry (`exec.ErrDot` refused) or an absolute path; its final path (links and junctions followed, `\\?\` stripped) must lie outside the repository and the current directory by file identity; device and UNC paths are refused; only operator layers set `model.run` | `gateway/command_test.go:TestSplitCommandLineRefuses`, `TestNewCommandRefuses`, `TestNewCommandIgnoresCurrentDirectory`; `gateway/command_windows_test.go:TestNewCommandRefusesWindowsPathsIntoRepo`; `gateway/command_unix_test.go:TestNewCommandRefusesLinkIntoRepo`; `config/command_test.go` |
| C2 | The CLI leaks the operator's secrets or reads the repository | Environment is `PATH`, `HOME`, locale and Windows start-up variables plus declared `model.env` names only; working directory is a fresh empty temp directory; stderr is discarded | `gateway/exec_test.go:TestExecIsolatesProcess` |
| C3 | The CLI hangs, drips output, floods memory or leaves a helper running | `model.timeout_seconds` kills it; stdout capped at `model.max_output_bytes`; a two-second wait delay bounds grandchildren holding the pipe; on Unix the CLI's whole process group is killed on timeout, cap and normal exit, before the working directory is checked; output decoded like an HTTP reply. **Residual (Windows):** only the CLI itself is killed (no job object without `x/sys` or `unsafe`), so a helper it started can outlive the run | `gateway/exec_test.go:TestExecFailsClosed`; `gateway/proc_unix_test.go:TestExecKillsProcessTree`; `models/command_test.go:TestCommandContractRejects` |
| C4 | The CLI has tools and injected code makes it act on the host | Tool canary at `creep doctor` and every scan start (trap prompt: create a file, run a command, random names) fails the run with exit 3 and the missing flag; on every call, anything left in the working directory drops the reply (`tool_use` in `egress.log`). **Residual:** tools that only read, or write outside the working directory, are not detected; the working directory is empty and never the repository, but a CLI that can still read (C6: `host_reads: unbounded`) reaches files under HOME | `models/canary_test.go:TestCanaryCatchesTools`, `TestCanaryCachedPerRun`, `TestCanaryFailsClosed`; `cli/modelcmd_test.go:TestScanAbortsWhenCommandHasTools`, `TestDoctorRunsCanary`; `gateway/exec_test.go:TestExecToolUseNamesEntries`; `models/protect_canary_test.go:TestToolCanaryProtection` |
| C5 | A command call skips redaction, consent or `egress.log` | `gateway.Command` is opaque and runs only through `EgressLog.Exec`, which has `Send`'s order: consent, budget, fsynced request line, run, result line | `gateway/command_test.go:TestCommandIsOpaque`; `gateway/exec_test.go:TestExecLogsWriteAhead`, `TestExecRefusalsRunNothing`, `TestExecPolicyConsent`; `cli/modelcmd_test.go:TestScanThroughCommandModel` |
| C6 | A preset (#7) runs another program, turns tools on, or is chosen or changed by the repository | Presets are embedded data (`go:embed`), never read from disk; closed schema (unknown and duplicate keys, a second document, a program that is a path, a shell string for args, control characters are refused); tools-off flags are listed and must be present in args; `model.preset` cannot be set in the project file, and neither can `model.name` when the preset passes it to the CLI (`ollama run` would pull a model the repository names); `model.name` never starts with `-` or holds spaces or quotes; a preset next to `model.run` or a non-command contract is an error. The canary still checks every preset at run time. Every preset declares `verified` (only `claude-code` is checked with the real CLI; unverified presets warn) and `host_reads`; `codex` (shell commands under a read-only sandbox still read HOME) and `gemini` (read-only tools, web search, MCP from its settings) are `unbounded`, and `creep doctor` and every scan print an escaped warning before the canary ([ADR 0015](adr/0015-model-presets.md)). `model.contract` cannot be set in the project file either, and a preset under a policy lock on `model.run` or `model.contract` (even one pinning the default) is a config error (`config/preset_test.go:TestPresetRespectsPolicyLocks`). **Residual:** an `unbounded` preset can still read host secrets (`~/.ssh`, `~/.aws`) and send them to its provider unredacted (Medium; prefer `claude-code` or `ollama` for untrusted code); a CLI's own settings (hooks, MCP servers) are outside the preset; flags are verified by a manual check per preset change | `presets/presets_test.go:TestEmbeddedPresets`, `TestSchemaRejects`, `TestDuplicatePreset`, `TestModelNameCannotInjectArguments`, `TestLookupUnknown`; `config/preset_test.go:TestProjectCannotChoosePreset`, `TestPresetRejects`; `cli/preset_test.go:TestPresetsRunTheCanary`, `TestScanWarnsWhenPresetReadsHost`, `TestProjectFileCannotSelectPreset` |

### 4.3 Network attacker

| ID | Threat | Mitigation | Held by |
|---|---|---|---|
| N1 | Read or change traffic | TLS with hostname verification; plain `http://` only to loopback (`localhost`, 127.0.0.0/8, ::1) | `gateway/client_test.go:TestPlainHTTPRefused`, `TestTLSVerifiesHostname`, `TestPlainHTTPToLoopback` |
| N2 | SSRF, DNS rebinding, cloud metadata | Allowlist checked before any DNS lookup; numeric host tricks rejected; each host resolved once and pinned; an answer with any non-public address refused whole; an IP entry never vouches for a name | `gateway/client_test.go:TestNotAllowedFailsBeforeDNS`, `TestResolvedIPIsPinned`, `TestPrivateResolutionRefused`, `TestIPEntryDoesNotVouchForNames`; `gateway/host_test.go` |
| N3 | A proxy variable routes traffic through the attacker | Proxy environment variables are ignored | `gateway/client_test.go:TestProxyEnvIgnored` |
| N4 | A redirect downgrades to HTTP or changes port | Refused | `gateway/redirect_test.go:TestRedirectDowngradeRefused`, `TestRedirectToAnotherOriginRefused` |

### 4.4 Local user

| ID | Threat | Mitigation | Held by |
|---|---|---|---|
| L1 | Read `egress.log`, payloads or run state | Files 0600, directories 0700; `egress.log` is never opened through a link, onto a file others can read or own, or one with a second hard link | `gateway/egress_test.go:TestFileModes`, `TestOpenRefusesUnsafePaths`, `TestOpenRefusesSharedLog` |
| L2 | Plant or swap the consent store | Refused when it is a link, another user's or writable by others; replaced atomically | `gateway/consent_store_test.go:TestBadStoreRefused`, `TestStoreSwapRefused`, `TestUnsafeStoreDirRefused` |
| L3 | Plant state in a shared `.creep` | The state directory is refused when writable by others; lines need the user's HMAC | `state/run_test.go:TestOpenRefusesUnsafeDir`, `TestFileModes`; `state/trust_test.go:TestUnsignedCacheEntryNeverServed` |
| L4 | Edit `egress.log` after the run as the same user | **Residual.** The log is an audit aid against `creep`, not against the account that runs it: the request line is fsynced before any byte is sent, so `creep` cannot send unlogged |

### 4.5 Malicious contributor or upstream

| ID | Threat | Mitigation | Held by |
|---|---|---|---|
| S1 | A new dependency brings attack surface | Direct dependencies need an ADR in `docs/adr/dependencies.txt`; `go mod tidy -diff`; module-graph and binary caps; no `go.work`, `vendor/` or local replace | budget; `make check` (`tidy`) |
| S2 | A network, exec or raw-syscall path outside the gateway | Import and reach rules over shipped code, tests and tooling; `os.StartProcess`, `os.NewFile` and raw syscalls on allowlists; depguard in the editor | `tools/budget/gateway_rule_test.go:TestNetImportFailsBudget`; `imports_test.go`; `guards_test.go:TestProcessUsesFixtures` |
| S3 | A tampered vendored rule set or grammar | `redact/rules/gitleaks.toml` pinned by SHA-256 and rule count; grammars by `SHA256SUMS` | `redact/rules_test.go:TestVendoredRulesUnchanged`; `static/grammar_test.go:TestEmbeddedGrammarsMatchSums` |
| S4 | A workflow leaks a token or runs untrusted code with secrets | Actions and images pinned by digest; no `pull_request_target`; workflows start from `permissions: {}`; actionlint and zizmor | budget (`workflow.go`); CI `workflows` job |
| S5 | Known-vulnerable code or a committed secret | govulncheck, gitleaks over the full history, CodeQL, dependency review, Scorecard | CI |
| S6 | The review loop is weakened quietly | Pinned policy phrases in AGENTS.md, CONTRIBUTING.md and the PR template; changing the loop needs an ADR | `tools/budget/policy_test.go`; budget |
| S7 | Release tampering | `v*` tags immutable and admin-only; immutable releases; the `release` environment needs the maintainer's approval and is the only job with write or OIDC permissions; the tagged commit must be on `main` or a `release/*` branch; cosign keyless signature of `checksums.txt`, SBOM per archive and build provenance, verified by the workflow before the draft is published; pinned, checksum-verified release tools; reproducible builds | `.github/rulesets/`, `.github/settings/` (`make rulesets`); `.github/workflows/release.yml` (`dry-run` job tests the ancestry guard and reproducibility on every PR touching the release files) |

## 5. AGENTS.md invariants

Every invariant in [AGENTS.md](../AGENTS.md#invariants--never-break-these) maps to the threats it answers and to what enforces it.

| Invariant | Threats | Enforced by |
|---|---|---|
| 1. Only `internal/gateway` may import `net/http` or open network connections | R4, M5, N1–N4, S2 | budget import and reach rules (`imports.go`, `reach.go`, `procs.go`); depguard; opaque `gateway.Client` (`gateway/api_test.go:TestNoRawHTTPClientExported`) |
| 2. Every model call goes through the gateway, which redacts first and writes `egress.log` | R10, R11, M6, L1, C5 | `models` cannot import networking and sends only through `gateway.Call` (`models/egress_test.go:TestReservationIsEnforcedByGateway`); command models only through `EgressLog.Exec` (`models/command_test.go:TestCommandContractThroughEgressLog`); `gateway/scan_test.go`; `gateway/consent_test.go:TestSendWithConsentLogs`; `calibrate/egress_test.go:TestRunGoesThroughGateway`; write-ahead log (`gateway/egress_test.go`) |
| 3. The planner receives only IDs, enums and booleans, never repository text | R1, R2, M2 | Reflection tests on `planner.Input`, `planner.Plan`, `reader.Signal` and `static.Graph`; layer table (`planner` ↛ `reader`, `static`, `redact`) |
| 4. Model output is never executed on the host; PoCs run only in the sandbox (v0.2) | M1, R14, C4 | Closed-struct decoding; no product package but `internal/gateway` and `internal/scanrun` may start a process (budget): the gateway starts only the operator's model CLI with the prompt on stdin, and the tool canary refuses a CLI that acts on its prompt; scanrun runs only installed scanners with fixed arguments (ADR 0013). v0.1 has no sandbox, so it generates and runs no PoC at all |
| 5. No telemetry; no network calls except to configured model endpoints | R4, N2, S2 | Invariant 1 plus the allowlist and consent: the gateway reaches only `egress.allow` entries the operator configured; no update check exists |
| 6. No new direct dependency without an ADR | S1, S3 | budget dependency allowlist (`docs/adr/dependencies.txt`); `go mod tidy -diff` |

## 6. Result honesty

A scanner that silently skips work is a security problem: a CI gate would pass code nobody looked at (A5).

- Every finding is `verified`, `probable`, `discarded` or `not evaluated`; every class is covered, partial or not evaluated (`report/report_test.go`).
- An incomplete run (the scan stopped, a run cap was hit, a file was refused, a sink was left unplanned, the run log did not end complete) is marked incomplete in SARIF, JSON and Markdown and exits 4, which wins over the gate's 1 ([ADR 0007](adr/0007-exit-code-incomplete.md), [ADR 0009](adr/0009-scan-and-why-contract.md); `exitcode/exitcode_test.go:TestForReportNeverCleanWhenIncomplete`, `report/report_test.go:TestIncompleteMarkedInEveryFormat`, `cli/scan_test.go:TestScanExitCodes`).
- The data-handling section is read from `egress.log` and fails closed on any line it cannot account for (`report/egress_test.go:TestSummarizeEgressFailsClosed`).
- A recorded run replays to the same report and exit code with no model call (`cli/scan_replay_test.go:TestScanReplay`).

## 7. Not built yet: requirements

These parts are on the roadmap, not on `main`. The PR that adds one must meet these requirements and update this document.

| Part | Requirements |
|---|---|
| semgrep (ADR 0010, ADR 0013) | Detected only. Running it needs creep-shipped local rules (a new ADR), `--metrics=off`, no registry or repository-chosen config, and the `internal/scanrun` rules gitleaks and osv-scanner follow |
| Recipes (v0.3; presets are built, §4.2a C6) | Data, never code; recipes pinned by commit in `creep.lock`; they cannot set endpoints, consent, gates or redaction, and cannot come from the scanned repository |
| Sandbox and PoC verification (v0.2) | No internet (internal network only); never on the host; model-written PoCs run only inside it; `verified` is reachable only through it |

## 8. Out of scope

- Vulnerabilities `creep` fails to detect: they are false negatives, tracked as issues, not security bugs ([SECURITY.md](../SECURITY.md)).
- An attacker who already controls the user's account, the Go toolchain or the operator's configuration (user file, `--config`, `CREEP_POLICY`, flags): operator layers are trusted by design and may loosen gates.
- The model provider's own handling of the redacted data it receives: consent per endpoint is where the user decides that.
