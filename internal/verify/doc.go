// Package verify turns a model's proof of concept, a core-owned template
// with closed parameters, into raw requests for the app under test and
// judges what came back with the template's own oracle.
//
// It exists so that the model never writes code to run (AGENTS.md
// invariant 4, ADR 0019). A PoC is a Request: a template ID
// (http_request, http_sequence, sql_payload, path_payload) and that
// template's typed parameters, decoded as a closed struct
// (models.Complete refuses unknown, duplicate and case-variant keys) and
// checked by Validate before anything runs:
//
//   - The model picks a method, a path, headers and a body, each from a
//     closed enum or a bounded string over a fixed alphabet. It never
//     picks a host, a scheme, a port or a forwarding header: every
//     request goes to sandbox.AppHost on the port the caller gives, and
//     creep writes Host, Content-Type, Content-Length and Connection
//     itself.
//   - Payloads are creep's: the model marks where one goes
//     (__CREEP_PAYLOAD__ or __CREEP_NONCE__) and picks its kind from an
//     enum, and creep writes minimal, non-destructive text (a pg_sleep,
//     an empty marker table, a read of the canary file it planted in the
//     app, an inert tag around a fresh nonce).
//   - Oracles are creep's, per template, never the model's: the probe
//     unescaped in an HTML response, a delay measured against baselines
//     sent before and after it by the same runner, the canary file's
//     content absent from the baseline, or the marker table in the run's
//     database. A status the model expects only narrows the reflect
//     oracle: a harmless request can return it too, so it never verifies
//     on its own. Each run has a fresh nonce, so repeated runs are
//     independent.
//
// Run sends the requests only through a Runner, which *sandbox.Sandbox
// implements: one hardened runner container on the run's internal
// network, after the network canary, with the requests as read-only files
// and never on a command line. This package starts no process and opens
// no connection itself.
//
// Repeat runs a PoC several times (DefaultRuns in a scan, #25, ADR 0020)
// and rates it: every run verified, some (intermittent), or none, which
// never holds, so no finding is verified without a run that verified.
// NewBundle keeps a held PoC as a reproduction bundle for creep
// reproduce, with every text the model or the app wrote passed through
// the caller's Scrub (redact.File): verify may not import redact, so a
// bundle cannot be made without one. The PoC prompts (prompts/, one per
// tier) and the closed Schema are data the CLI sends through the gateway.
package verify
