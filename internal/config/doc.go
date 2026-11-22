// Package config resolves creep's effective configuration from layers.
//
// It exists so that every command sees one validated Config and can say where
// each value came from. Layers apply in this order, later ones overriding
// earlier ones key by key (lists are replaced, never merged):
//
//  1. built-in safe defaults
//  2. org policy (the file named by CREEP_POLICY): `locked`, `limits`, `defaults`
//  3. user file (~/.creep/config.yaml)
//  4. project file (./creep.yaml)
//  5. CLI flags
//
// An explicit --config file replaces layers 3 and 4: it is read instead of
// both, so a CI job can pin one reviewed file and ignore whatever the runner's
// home directory or the checked-out repository contains. Policy still applies.
//
// Safety rules enforced here:
//   - Keys are typed structs decoded strictly; an unknown key is an error.
//   - Fixed protections (no internet in the sandbox, redaction, egress.log,
//     model output never run on the host, planner never reads code) have no
//     keys at all, so no layer can express turning them off.
//   - A key the policy locks cannot be set by any later layer.
//   - A gate looser than the policy limit is rejected.
//   - The project file may only make gates stricter: a project gates.pr or
//     gates.nightly looser than the built-in default, the policy limit or
//     the gate the layers before it set (policy defaults, user file) is
//     rejected, so a pull request cannot loosen the gate that judges it.
//     Operator layers (user file, --config, policy) may still loosen.
//   - The scan mode (pr, nightly) picks which gate judges a run and is not
//     a key: it comes from --mode or a GitHub Actions schedule event
//     (ChooseMode), so no file can pick it. Reading a gate without
//     verification only raises its status to probable (UnverifiedGate).
//   - The project file comes from the repository being scanned, which is
//     untrusted, so it cannot set where code is sent (model.endpoint,
//     egress.allow), which program receives it (model.run, model.env,
//     model.preset, model.contract, model.name), the model tier, the
//     sandbox, the scanners or the report outputs (projectForbidden), and
//     may only lower the operator's limits (projectLowerOnly).
//     A preset (internal/presets) resolves into model.run and contract
//     command after every layer has applied (preset.go).
//   - Consent to send code to an endpoint is not a config key: only the
//     policy's consent list grants it (PolicyConsent), plus, outside CI,
//     the user's own answers that the gateway stores. InCI is the single
//     definition of a CI run.
//
// The package does no file I/O: callers read the files (internal/cli does it
// without blocking on FIFOs) and pass the bytes in.
package config
