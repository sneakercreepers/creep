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
//     picks a host, a scheme or a port: every request goes to
//     sandbox.AppHost on the port the caller gives, and creep writes Host,
//     Content-Type, Content-Length and Connection itself.
//   - Payloads are creep's: the model marks where one goes
//     (__CREEP_PAYLOAD__) and picks its kind from an enum, and creep
//     writes minimal, non-destructive text (a pg_sleep, an empty marker
//     table, a read of /etc/passwd). A fresh nonce (__CREEP_NONCE__) is
//     the only value a reflection oracle accepts, so no answer the app
//     always gives can pass for a verified one.
//   - Oracles are creep's: a status the model expects, the nonce
//     reflected, a delay measured against a baseline request in the same
//     runner, the file's marker absent from the baseline, or the marker
//     table in the run's database.
//
// Run sends the requests only through a Runner, which *sandbox.Sandbox
// implements: one hardened runner container on the run's internal
// network, after the network canary, with the requests as read-only files
// and never on a command line. This package starts no process and opens
// no connection itself.
package verify
