# ADR 0019: PoC templates with closed parameters, sent from a runner container

- **Status:** Accepted (maintainer, 2026-11-21)
- **Date:** 2026-11-21
- **Deciders:** @Ludocius
- **Amended by:** [ADR 0020](0020-poc-repetitions-and-bundle.md) (each PoC runs `verify.DefaultRuns` times from `creep scan`, with a reproduction bundle and `creep reproduce`)
- **Amends:** [ADR 0016](0016-sandbox-runtime.md) (two more containers join the run network: the PoC runner, after the canary, and the database marker lookup; the app container gets one read-only mount, creep's canary file)
- **Changes:** a new layer-6 package `internal/verify`, whose row was already in the layers table; a new stable contract, the PoC parameter schema (`verify.Request`); `sandbox.Exchange`, `sandbox.DatabaseHasTable`, `sandbox.AppCanary`, `sandbox.RunnerImage`, `sandbox.AppHost` and `sandbox.AppCanaryFile`
- **Fitness function:** the rows "A PoC is a closed template the model cannot escape", "PoC requests run only in the runner container" and "A PoC oracle cannot be faked" of [architecture.md §9](../architecture.md#9-fitness-functions)

## Context

#24 lets a model prove a finding by running a proof of concept against the app creep built (#23). The model read untrusted code, so what it writes must never run as code, on the host or anywhere (AGENTS.md invariant 4). The issue asks for core-owned templates (`http_request`, `http_sequence`, `sql_payload`, `path_payload`), a model output of a template ID plus typed parameters validated against a schema, a success oracle per template (status, body marker, timing, database side effect), execution only inside the runner container, and golden tests per template. #25 then runs each PoC several times, keeps a reproduction bundle and adds `creep reproduce`.

Constraints:

- `os/exec` is allowed only in `gateway`, `scanrun` and `sandbox`, and `net` only in `gateway`, so `verify` can neither start a container nor open a connection.
- The sandbox's run network is internal, gets a canary before every batch, and publishes no port (ADR 0016 and its amendments). The app joins it as `app` through `StartApp`.
- The model's parameters are untrusted text: no shell may ever see them, every size needs a bound, and the model must not be able to pick where a request goes.
- Payloads must stay minimal and not weaponized.
- A false `verified` is the worst failure creep can have. So no oracle may take its success value from the model: a model, or prompt-injected code steering it, could otherwise name what a harmless request returns.

## Options

| Option | Pros | Cons |
|---|---|---|
| A. The model writes a script or a curl command line that runs in a container | Expressive | Model text becomes code and argv; nothing bounds what it does inside the container; a shell sees it |
| B. creep sends the requests itself from the host | No extra container | Needs `net` outside the gateway; the app would need a port reachable from the host, which the run network refuses by design |
| C. Closed templates in `verify`; creep renders each request to raw bytes; a fixed BusyBox runner container on the run network sends them, with the bytes as read-only mounted files | No model text in any argv or script; the host never reaches the app; reuses the pinned canary image, the hardened profile and `RunBatch`'s canary | The client is BusyBox `nc`, so requests are HTTP/1.1 written by creep, and timing has 10 ms resolution (`/proc/uptime`) |

For the oracles:

| Option | Pros | Cons |
|---|---|---|
| a. The model names the expected status or marker | Covers any flaw | A harmless request passes for an exploited one whenever the model expects what it returns: a false `verified` |
| b. creep decides each oracle per template from what only an exploited request can produce: its own probe, payload, side effect or planted file, against a baseline where timing or content could be ambient | No success value comes from the model | Flaws with no such evidence (an access-control flaw shown only by a status) cannot be verified yet |

## Decision

Option C with oracle b: it is the only one where nothing the model writes is ever interpreted by a shell or a program, the host never reaches the run network, and no model text decides `verified`.

**The schema (stable contract).** The model returns a `verify.Request`, a closed struct that `models.Complete` decodes (unknown, duplicate and case-variant keys refused, then `Validate`):

- `template` is one of `http_request`, `http_sequence`, `sql_payload`, `path_payload`, and exactly that template's parameters are set.
- A `Call` is `method` (GET, POST, PUT, PATCH, DELETE), `path` (origin form: one leading `/`, at most 1024 bytes of RFC 3986 path and query characters, valid `%` escapes, no `//` prefix, space, `#`, `\` or control byte), `headers` (at most 8, names from a closed list: Accept, Accept-Language, Authorization, Cookie, Origin, Referer, User-Agent, X-Api-Key, X-Csrf-Token, X-Requested-With; no `X-Forwarded-*`, `Forwarded` or other routing header; values 1 to 1024 printable ASCII characters), `content_type` (empty, `json`, `form` or `text`) and `body` (only with a content type, not on GET, at most 8 KiB of UTF-8, valid JSON for `json`, URL-encoded for `form`).
- There is no host, scheme or port. creep writes `Host: app:<port>`, `Content-Type`, `Content-Length` and `Connection: close`; the port comes from the caller (`verify.Target`), never from the model.
- `http_request`: one `request` and an `oracle`, whose only kind is `reflect`: the `__CREEP_NONCE__` placeholder 1 to 4 times in the request, which creep replaces with its probe `'"><creep<nonce>>` (a fresh random nonce inside an inert tag, after both quotes), URL-encoded in a path or form, JSON-escaped in JSON, as is in a header or text body. Verified only when the response's every `Content-Type` is HTML (`text/html`, `application/xhtml+xml`) and its body holds the whole probe unescaped. The oracle's `status` is 0 or a status from 100 to 599 that the response must also have: it narrows the oracle and never verifies on its own. A `status` oracle kind is refused.
- `http_sequence`: an `auth` call with no placeholder, a `session` (`cookie`: the auth response's `Set-Cookie` pairs; `bearer`: one top-level string field `token_field` of its JSON body), then the `request` with that session and the same oracle. The session values come from the app and are checked to header-safe alphabets; anything else is `auth_failed`.
- `sql_payload`: one request with `__CREEP_PAYLOAD__` exactly once in its path or body, a `context` (`string`, `numeric`) and a `technique`: `delay` (`pg_sleep(3)`; verified when the payload request takes at least 2.5 s longer than each of two baseline requests sent just before and just after it by the same runner, so an app that slows a later request down slows the last baseline too) or `marker` (a stacked `CREATE TABLE creep_<nonce> ()`; verified when that table exists in the run's database). The run's database is PostgreSQL, so the payloads are.
- `path_payload`: one request with the payload placeholder, a `style` (`relative` or `encoded` with a `depth` of 1 to 12 `../` steps, or `absolute`) toward `/etc/creep-canary`, a file creep plants in the app's container with fresh random content (`sandbox.AppCanary`); verified when that content is in the payload response and not in the baseline's. A sample `/etc/passwd` in the repository cannot pass for it.
- Every payload is creep's text, encoded for where it goes (URL-encoded in a path or form, JSON-escaped in a JSON string). None deletes or changes application data, and none reads a file creep did not plant.
- Each `verify.Run` has its own fresh nonce, so a marker table or stored probe from an earlier run of the same PoC never verifies a later one (#25 repeats each PoC).
- Outcomes are closed: `verified`, `not_verified`, `no_response`, `auth_failed`, `no_database`. A sandbox error (canary abort, timeout, Ctrl+C) or a missing canary file is an error, never an outcome.

**The runner (amends ADR 0016).** `sandbox.Exchange(ctx, port, requests)` writes each request (1 to 4, each at most 64 KiB) as a file in the sandbox's 0700 work directory, mounts them read-only at `/poc/r<i>`, and runs one container from `RunnerImage` (the pinned BusyBox of the canary) through `RunBatch`, so the canary runs first and the hardened profile applies. Its script is fixed and holds only creep's numbers: wait up to 30 s for the app's port, then for each file `timeout 20 nc app <port> < /poc/r<i> | head -c <cap+1>`, timed by `/proc/uptime` inside the container. It prints one `r<i> <start> <end> <bytes>` line per request before any response byte, then the responses; creep reads it strictly, so a response cannot pose as another request's timing or bytes. Each response is capped at 192 KiB. `Exchange` needs a started app.

`StartApp` writes `creep-canary-` and 32 random hex digits to a file in the work directory and mounts it read-only at `/etc/creep-canary` in the app's container; `AppCanary` returns the content. That is the only change to the app container.

`sandbox.DatabaseHasTable(ctx, table)` looks up a table named `creep_` and 16 to 48 lowercase letters or digits (creep's marker) with a fixed `psql` query from a client container on the run network, the synthetic password in its environment only. Like the readiness poll, it runs creep's own command, so it has no canary of its own.

`verify` depends on a three-method `Runner` interface (`Exchange`, `DatabaseHasTable`, `AppCanary`) that `*sandbox.Sandbox` implements; it starts no process and opens no connection.

## Consequences

- A model can no longer reach anything but the app: no host, no port, no scheme, no framing or forwarding header is expressible, and the runner's script names only `app` and creep's port.
- No oracle takes its success value from the model, so a model, or code that prompt-injects it, cannot make a harmless request `verified`. Access-control flaws that only a status would show (an IDOR, a missing check) have no template oracle yet; they stay unverified, never verified by a status.
- `verify.Request` is a public contract: adding a template or an enum value is additive; changing a field or a rule needs a note in the PR, and an ADR if it breaks a stored PoC (#25's bundle).
- Requests are HTTP/1.1 over plain TCP. TLS inside the run network, HTTP/2 and WebSocket are not supported; an app that needs them gets `no_response`. A compressed response body is not decoded, so its oracle does not hold.
- Residual: the reflect oracle proves the probe reached HTML unescaped, not that a browser runs it there; inside a comment, `<textarea>` or `<title>` it would still count. An app written to recognize creep's payloads (echo the probe, sleep on `pg_sleep`, read the canary file, create the table itself) can make itself verified; that reports a flaw in the scanned repository itself, and #25's repetitions do not narrow it.
- Tests: golden requests and outcomes per template against a vulnerable app and its safe twin (`internal/verify/golden_test.go`); protection tests `TestInvalidPoCRejectedBeforeRun`, `TestModelCannotPickHost`, `FuzzBuiltRequestStaysOnApp`, `TestOraclesCannotBeFaked`, `TestStatusNeverVerifies`, `TestRunsAreIndependent` (`internal/verify`), `TestExchangeRunsOnlyInRunner`, `TestRunnerAnswerCannotBeForged`, `TestAppCanaryPlanted` (`internal/sandbox`); the real-engine test `TestRealRunnerReachesTheApp`.
- Not wired into `creep scan` yet: #25 runs each PoC N times against the build `creep scan` makes, keeps the bundle and adds `creep reproduce`.

## Amendment: verified against a real framework app (#364)

- **Status:** Proposed
- **Date:** 2026-11-27
- **Changes:** none to `verify.Request`, the templates or the oracles; a new live job proves them against a real app.

### Context

The golden tests ran every template only against Go fakes, so no PoC had been verified against a real web framework and a real PostgreSQL driver.

### Decision

`testdata/apps/flaskpg` is a Flask app on a digest-pinned Python image, with pg8000 and its dependencies committed as wheels pinned by sha256 in `requirements.txt`, so the `--network=none` build installs them offline. Its vulnerable variant has an SQL injection (an f-string in `LIKE`) and a path traversal (`send_file(os.path.join(...))`); the safe twin binds the parameter and uses `send_from_directory`. `live-verify.yml` runs `creep scan --mode nightly` with the real sandbox on both variants (`TestLiveAppVerifies`), nightly, on dispatch and on pull requests that touch the sandbox, verification or the app, with the repository's synthesized model, so no key and no endpoint. The model claims both classes on both variants and gives each its PoC (`sql_payload` with the `delay` technique; `path_payload`, encoded, depth 6); the job fails unless both are verified 5 of 5 on the vulnerable variant and nothing is verified on the safe twin.

### Consequences

- The `marker` technique (a stacked `CREATE TABLE`) does not verify on pg8000, whose extended query protocol refuses several statements in one query; the `delay` technique does. Apps on such drivers are verified by delay only.
- The model answers are synthesized in the test (reader claims by sink line, the PoCs of the committed PoC fixtures), not replies recorded from a live model; recording them from a live run is #356.
- The committed wheels are linux/amd64 only (`markupsafe` is a CPython 3.13 manylinux x86_64 build), so the app builds only on an amd64 engine.
- The live job needs Docker or Podman and the three pinned images (BusyBox, PostgreSQL, Python); it skips unless `CREEP_LIVE_VERIFY` is set, so `make check` stays offline.
