// Package actionscripts tests the shell scripts behind the creep GitHub
// Action (action.yml at the repository root, action/*.sh; ADR 0023).
//
// The Action runs on other people's runners with their tokens and model
// keys, so each script's refusals are protections: the event and fork
// policy, the checksum and build-provenance check before a downloaded
// binary runs, exit 4 failing the job like exit 1, the baseline read from
// the base commit, and a pull request comment that carries only creep's
// escaped Markdown report. The tests run each script under bash with fake
// gh and creep programs on PATH, so they need no network, token or release.
// They skip on Windows, where the Action does not run; CI runs them on
// Linux. The package has no product code and the layers table
// (internal/tools/*) keeps it out of the binary.
package actionscripts
