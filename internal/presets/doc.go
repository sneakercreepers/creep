// Package presets turns `model: { preset: <name> }` into a model CLI
// command line, from reviewed data files embedded in the binary.
//
// It exists because the flags that make a CLI non-interactive and switch
// its tools off change with every CLI release, and getting them wrong lets
// a model that reads untrusted code write files or run commands. Presets
// keep those flags in one reviewed place, as data (one *.yaml file per CLI
// next to this file), so a new CLI needs a reviewed data file, not code:
//
//   - Presets are embedded with go:embed and are never read from disk, so
//     neither the scanned repository nor the working directory can add or
//     change one. internal/config also refuses model.preset in the project
//     file, like model.run.
//   - The schema is closed (schema.go): unknown and duplicate keys, a second
//     YAML document, a name that is not a plain lowercase word, a program
//     that is a path, an argument with control characters or both quote
//     kinds, and a tools_off flag missing from args are all errors. args is
//     a list, never a shell string; CommandLine quotes each argument for
//     the gateway's shell-free splitter.
//   - tools_off lists the arguments that switch the CLI's tools off. They
//     must appear in args, so a preset cannot drop one silently, and the
//     tool canary (internal/models) still checks the running CLI: presets
//     are a convenience, never the protection.
//   - host_reads declares whether the CLI can still read outside its empty
//     working directory (read-only tools, a shell under a read-only sandbox,
//     web search). The canary cannot see reads, so the CLI warns before every
//     doctor and scan run of an "unbounded" preset (ADR 0015).
//   - The only value that reaches argv from configuration is model.name,
//     for presets whose args hold the {model} placeholder. It must look like
//     a model name (no leading "-", no spaces or quotes), and config refuses
//     it from the project file for such presets.
//
// TestEmbeddedPresets validates every embedded file, so `make check` and CI
// fail on a broken preset.
package presets
