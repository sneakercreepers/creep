// Command budget enforces creep's supply-chain and size budget in CI.
//
// creep reads untrusted source code and talks to model endpoints, so every
// dependency is attack surface. Reviews miss slow growth, so this tool fails
// the build when a direct or tool dependency lacks an ADR, a versioned
// replace swaps in a module without one, code outside the module-root
// internal/gateway imports a package that can reach the network (net,
// crypto/tls, syscall, unsafe, cgo, os/exec or go/build outside an
// allowlist…), reaches net or a process start (os/exec, internal/tools, or a
// third-party package with raw calls or non-Go files) through any chain of
// imports in a release build (linux, darwin, windows × amd64, arm64, cgo
// off) or the Linux CI build (cgo on), or calls os.StartProcess or
// os.NewFile, the repository holds non-Go sources (assembly, C, .syso…), a go.work, vendor/
// or a local replace, a package imports outside the layers table of
// docs/architecture.md, a Go file passes 400 lines, the module graph or the
// release binary outgrows its cap, or a workflow uses pull_request_target,
// an action not pinned by commit SHA, a docker:// action or a container or
// service image not pinned by @sha256 digest, or YAML a line scan cannot
// resolve.
//
// It is a static backstop, not a sandbox: it reads source text and cannot see
// everything a determined author can hide. The reach checks follow only the
// import graphs of those builds: a main-module file for another platform
// (freebsd, say) or a custom build tag, and a third-party import found only
// in a dependency's ignored files, are outside them. None of those reach a
// release binary or a CI run. Code review and CODEOWNERS remain required, and
// zizmor and actionlint in CI are the authoritative workflow checks.
//
// It is stdlib-only and runs with `make budget`.
package main
