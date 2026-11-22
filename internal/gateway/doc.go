// Package gateway is the only code in creep that may touch the network or start a model CLI.
//
// It exists so that every byte leaving the machine passes one reviewable
// choke point (AGENTS.md invariants 1, 2 and 5):
//   - It is the only package allowed to import net, net/http, crypto/tls and
//     the other networking packages. `make budget` fails the build when any
//     other package, test files and dev tooling included, imports them or
//     reaches them through a dependency; golangci-lint's depguard rule gives
//     the same feedback in editors.
//   - Every model call is redacted first: each producer of repository text
//     that Call lists (FileScan, reader.Slicer and discovery) passes each
//     file whole through the run's redact.File and cuts only its output, and
//     a run that returns redact.ErrRunFull stops sending and is reported as
//     incomplete.
//   - Every request is recorded in egress.log, so a user can audit exactly
//     what was sent and where.
//   - It connects only to configured model endpoints; creep has no telemetry.
//
// NewClient returns an opaque *Client with no HTTP methods, so the only
// exported way to send is EgressLog.Send (a test checks that no exported
// API returns *http.Client, *http.Transport or http.RoundTripper). It
// enforces where requests may go, in this order and before any
// DNS lookup or dial:
//   - Allowlist: the URL host and effective port must match an egress.allow
//     entry. "host" covers only the scheme's default port (443 or 80);
//     "host:port" covers only that port. Hosts must be LDH DNS names whose
//     last label starts with a letter, or canonical IP literals without a
//     zone, so numeric tricks (2130706433, 0x7f.1, 0177.0.0.1, 127.1) never
//     reach a resolver. IPv4-mapped IPv6 is compared as IPv4.
//   - TLS: http:// is allowed only to loopback hosts, meaning exactly the
//     name "localhost", 127.0.0.0/8 and ::1. Names that resolve to loopback
//     (localhost.attacker.com, 127.0.0.1.nip.io) are not loopback hosts.
//   - Redirects: only to the same scheme, host and port as the first
//     request, at most 10. https→http and port changes are refused.
//
// The dialer then pins addresses: each allowlisted host is resolved once per
// client and later dials use only the pinned IPs (at most 8), while TLS still
// verifies the certificate and sends SNI and Host for the hostname. Only
// when every pinned address fails (not when the caller gives up) is the pin
// dropped, and the next dial resolves again under the same checks. A slow
// lookup holds only its own host, and a dial waiting on it returns when its
// own context ends. "localhost" is never resolved; it means
// 127.0.0.1, then ::1. A multi-label name is looked up fully qualified
// ("api.example.com."), so a system resolver cannot expand it with search
// domains; the allowlist and the pin keep the form without the dot. A DNS
// answer containing any non-public address (loopback, private, CGNAT,
// link-local and cloud metadata, multicast, documentation, test and
// benchmarking ranges, SRv6 SIDs, or NAT64, SIIT, ISATAP and 6to4 forms of
// those) is refused whole, always. A model on a private network is reached
// by allowlisting and requesting its IP literal ("10.0.0.5:8443"); that
// entry never vouches for a name resolving to it.
//
// Known limit, undecoded IPv4 embeddings: an IPv6 address can carry an IPv4
// address that some translator on the path will reach, in forms that cannot
// be recognized from the address alone. The well-known NAT64 prefix
// (64:ff9b::/96), SIIT (::ffff:0:0:0/96) and ISATAP interface IDs
// ([00|02]00:5efe:w.x.y.z) are decoded and judged by their IPv4; 6to4,
// Teredo, IPv4-compatible and local-use NAT64 prefixes are refused whole.
// A network-specific NAT64 prefix (RFC 6052, any /32 to /96 an operator
// picks, such as 2001:470:64::7f00:1) stays public. Reaching a non-global
// IPv4 through it needs an operator NAT64 that translates to such
// addresses, and TLS still verifies the hostname.
//
// DNS lookup, each dial and the dial over all pinned addresses, TLS
// handshake, response-header wait and response body (idle and total) have
// fixed default timeouts (client.go) until they get config keys.
//
// Proxy environment variables are ignored: a proxy resolves names itself,
// which would bypass the address checks and pinning above.
//
// Every model call goes through EgressLog.Send, which writes
// <run>/egress.log, one JSON object per line, mode 0600, opened with
// O_APPEND and never through a link or onto a file others can read, own or
// reach through a second hard link (the link count is read from the open
// handle, on Windows too). The run directory is the only path resolved by
// name: it is opened once as a directory handle, and egress.log and
// payloads are looked up relative to it, so swapping the run directory or
// an ancestor afterwards changes nothing. Send copies the payload before
// hashing it, follows no redirects (that would re-send the body unlogged),
// and strips userinfo and query from every error it returns.
// Each call gets a random ID and two lines:
//   - "request", written and fsynced before the request is built, with the
//     endpoint (scheme, host and path only: no userinfo or query), model,
//     purpose, byte count, sha256 of the exact body sent, redaction counts by
//     marker label, and payload_file. A failure here aborts the call before
//     any byte is sent.
//   - "result", after the reply, with a closed outcome enum, the HTTP status
//     and the tokens the provider reported. No error text, header or payload
//     byte is ever written to the log.
//
// The body itself is stored in <run>/payloads/<id>.payload (mode 0600, in a
// 0700 directory), so the user can check the hash and read what was sent.
//
// Accepted limits of the log (#113); each needs the user's own account or
// configuration:
//   - Windows ACLs: Go file modes do not express them, so the mode and owner
//     checks are skipped there and the run directory's inherited ACL decides
//     who can read the log and payloads. The state directory must sit where
//     only the user can read, such as under the user profile, not in a
//     folder whose ACL grants other users access (one created directly
//     under C:\ inherits modify access for every authenticated user).
//     Setting an owner-only DACL needs Windows security calls the syscall
//     package does not expose, so it waits for x/sys or an ADR.
//   - Run directory location: the state package creates it per run, with a
//     fresh name and mode 0700, under .creep/runs, which is refused when
//     writable by others; the path up to the run directory is trusted until
//     the one open here. Moving it out of the scanned repository is a
//     state-layout decision, not a gateway one.
//   - Endpoint path: the logged endpoint keeps its path, which the report's
//     data-handling section shows, so an endpoint with a credential in its
//     path ("/bot<token>/") is logged and reported verbatim. The endpoint
//     comes only from the operator's configuration (the project file cannot
//     set it), and the key belongs in CREEP_API_KEY, sent in a header that
//     is never logged; userinfo and query are stripped.
//
// Consent gates every Send before the payload file, the request line or any
// connection. It is per endpoint origin (scheme, host and effective port,
// normalized like egress.allow), never global:
//   - In CI (config.InCI) consent comes only from the policy file's consent
//     list (CI detection: config.InCI); nothing prompts and the local store
//     is ignored. A missing entry returns a *ConsentError whose ExitCode is
//     2; so does an unreadable or unsafe store (fail closed).
//   - Locally the policy, then the user's consent store (a 0600 JSON file of
//     origins, replaced atomically, refused when it is a link, another
//     user's or writable by others), then the injected Prompt. A yes is
//     stored, so each endpoint is asked once; a no is remembered for the
//     run only. TerminalPrompt declines without reading when stdin is not a
//     terminal.
//   - A refusal is not written to egress.log: the log records what was
//     attempted, and a refused call attempts nothing. The caller reports it.
//   - The scanned repository cannot grant consent: creep.yaml has no consent
//     key and the store lives in the user's directory, never the repo.
//
// FileScan is the gateway's own producer of Call payloads (scan.go):
//   - Each file is redacted whole by redact.File, then cut at line ends into
//     fragments of at most MaxFragmentBytes (a longer line goes alone, never
//     truncated). Only File output is cut, so no boundary splits a secret.
//     Fragments are not passed through Redact again: File already ran every
//     detector, and Redact would escape File's own markers.
//   - Fragment.Redactions counts the run's markers in the fragment by label,
//     for Call.Redactions.
//   - A file that cannot be read or that File rejects (ErrFileTooLarge;
//     ErrLineTooLong for minified, binary or CR-only files; any other error)
//     is never sent, raw or truncated, and is listed in ScanReport.NotScanned.
//   - redact.ErrRunFull from File, or from a Redact the caller makes inside
//     Send, and any other Send error stop the run: that file and every later
//     one are listed as not scanned, ScanReport.Incomplete is set and Run
//     returns the error. An incomplete scan is never a clean result.
//   - SkipReason is a closed enum so run output never quotes error text;
//     NotScanned.Path comes from the repository and must be escaped when
//     printed.
//
// The Budget (budget.go, aimd.go) limits every Send after consent and before
// the payload file, the request line or any connection; a nil Budget
// refuses every call:
//   - Each call reserves Call.ReserveTokens and one call against the run
//     (budget.max_tokens, budget.max_calls from the resolved config) and,
//     when set, against its endpoint origin's token limit. A call that would
//     exceed any of them returns a *BudgetError and, like a consent refusal,
//     writes and sends nothing. FileScan reports it as SkipBudget and stops
//     the run as incomplete. Reservations make concurrent calls unable to
//     overspend together.
//   - Usage reported by the reply replaces the reservation (capped at the
//     run limit); a call with no reported usage keeps it spent.
//   - Each endpoint origin has an AIMD concurrency limit: it starts at 1,
//     grows by one per 2xx up to MaxConcurrency, and halves (never below 1)
//     on 429 or 5xx. Waiting for a slot ends with ctx and returns the
//     reservation. The limit only bounds callers; the gateway starts no
//     goroutines of its own.
//
// A command model (a CLI such as claude -p, prompt on stdin, JSON on stdout)
// is the other egress path, and it lives here for the same reason
// (ADR 0014). NewCommand returns an opaque *Command; the only way to run it
// is EgressLog.Exec, with Send's order: consent and budget keyed on
// Command.Endpoint ("command://<program>-<hash>"), payload file and request
// line written and synced, then the run, then the result line (outcomes
// add tool_use, timeout and command_failed). The command line is split
// without a shell and refuses shell syntax; the program comes from an
// absolute PATH entry or an absolute path whose final path (links,
// junctions and \\?\ resolved) is outside the repository and the current
// directory by file identity; device and UNC paths are refused. Each run
// gets only the base and declared environment variables, an empty private
// working directory under the user cache directory (never the system temp
// directory, where other users could plant files a CLI reads from parent
// directories) and its own TMPDIR, a timeout and a stdout cap; stderr
// is discarded. On Unix the CLI's whole process group is killed after it
// exits or times out, before the working directory is checked; on Windows
// a timeout or the output cap kills the tree with taskkill /T /F from a
// drive-letter SystemRoot (no job object without x/sys or unsafe, #226),
// while a second handle opened right after the start pins the CLI's
// process ID, since os/exec closes its own as soon as the CLI exits; after
// a normal exit nothing is killed, since taskkill finds no tree under an
// exited process (residual, threat model C3). Anything
// left in the working directory means the CLI used a tool: the reply is
// dropped with a *ToolUseError.
package gateway
