# creep report

creep `v0.0.0-test` (commit `0000000`) · report schema 1

> **INCOMPLETE RUN** (reason `redact_run_full`): not everything was evaluated. This is not a clean result, whatever the findings below say.

## Findings

| ID | Class | Status | Location | Notes |
|---|---|---|---|---|
| `f1` | `sqli` | `verified` | `app/db.py:12` | `stable discovery: seen in 3 of 3 runs` |
| `f2` | `path_traversal` | `probable` | ``app/`tick`\|pipe.py:7`` | `unstable discovery: seen in 2 of 3 runs` |
| `f5` | `command_injection` | `probable` | `bad\xffutf8 #?%.py` |  |
| `f3` | `sqli` | `discarded` | `app/db.py:40` | `partial slice` |
| `f4` | `ssrf` | `not evaluated` | `svc/fetch.js:9` | `step cap` |

Run `creep why <id>` for the evidence behind a finding.

## Coverage by class

| Class | Status | Calibration detected / tasks | Recall 95% CI |
|---|---|---|---|
| `sqli` | `partial` | 9 / 10 | 0.596 – 0.982 |
| `path_traversal` | `partial` | 3 / 6 | 0.188 – 0.812 |
| `ssrf` | `not evaluated` | 0 / 0 | 0.000 – 1.000 |

## Not looked for

creep does not look for these classes in any language, so this report says nothing about them:

- memory-safety bugs in C, C++ and unsafe Rust, such as buffer overflows, use after free and format strings (`memory_safety`, CWE-119)
- cross-site scripting (`xss`, CWE-79)
- XML external entities (`xxe`, CWE-611)
- cross-site request forgery (`csrf`, CWE-352)
- open redirects (`open_redirect`, CWE-601)
- insecure direct object references (`idor`, CWE-639)
- missing authentication on a route or function (`missing_auth`, CWE-306)
- broken authentication, such as weak session, token or password checks (`broken_auth`, CWE-287)
- prototype pollution (`prototype_pollution`, CWE-1321)
- weak or misused cryptography (`weak_crypto`, CWE-327)
- race conditions (`race_condition`, CWE-362)
- regular-expression denial of service (`redos`, CWE-1333)
- business-logic flaws (`business_logic`, CWE-840)

**No class covers the 3 files left out by design (vendor 2, generated 1)**, listed under Not evaluated.

## Not evaluated

12 files were not evaluated in full; do not read this report as covering them.

| File | Reason |
|---|---|
| `www.evil.example/[link](http://x)<script>.js` | `too large` |
| `ok\x1b[31mred\x0anewline.py` | `line too long` |
| `bidi\u202egnp.exe` | `read failed` |
| `c1\u009b31mcsi.py` | `redact failed` |
| `del\x7fete.py` | `read failed` |
| `tag\U000e00411.py` | `read failed` |
| `lit\\u202egnp.exe` | `read failed` |
| `node_modules/pkg/index.js` | `vendor` |
| `node_modules/pkg/lib.js` | `vendor` |
| `api_pb2.py` | `generated` |
| `lib/after.py` | `run full` |
| `lib/later.py` | `run full` |

## Optional scanners

Only a scanner marked evaluated ran offline and evaluated its classes; for every other status they were not evaluated through it.

| Scanner | Status | Classes |
|---|---|---|
| `gitleaks` | `evaluated`; the repository's suppression file was not applied, so it hid no finding | `hardcoded_secret` |
| `osv-scanner` | `failed` | `vulnerable_dependency` |
| `semgrep` | `refused` | `xss`, `insecure_deserialization` |

## Data handling

3 requests, 2050 bytes after redaction, sent to 2 endpoints (from `egress.log`; each payload is in `payloads/`).

| Endpoint | Models | Requests | Bytes | Tokens in / out | Outcomes |
|---|---|---|---|---|---|
| `http://127.0.0.1:8080/v1/chat/completions` | `local\|model` | 1 | 50 | 0 / 0 | `http_error` 1 |
| `https://api.example.com/v1/messages` | `m-large`, `m-small` | 2 | 2000 | 300 / 40 | `no_result` 1, `ok` 1 |

Redacted before sending: `AWS_KEY` 3, `EMAIL` 1.
