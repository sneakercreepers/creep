// Command linkcheck proves on the linked binary that no third-party code in
// creep can open a connection or start a program (AGENTS.md invariant 1,
// ADR 0027).
//
// The import-graph checks in internal/tools/budget are per package: the
// MCP SDK's package holds HTTP and command transports next to the stdio one
// creep uses, so it reaches net and os/exec there. internal/tools/budget
// lets internal/mcp alone import it, and this tool replaces that check
// with an exact one: for every release target in .goreleaser.yaml it links
// cmd/creep with -ldflags=-dumpdep and walks the linker's graph from every
// third-party symbol. A path to a function in net, net/http, net/rpc,
// net/smtp, os/exec or crypto/tls, or to os.StartProcess, fails, unless
// that exact edge is in linkReviewed with its reason. It also parses every
// .go file of the module and refuses any SDK name outside sdkAllowed, so
// tests cannot use a network transport either.
//
// `make budget` runs it after internal/tools/budget. It is stdlib-only
// build tooling; the layers table (internal/tools/*) keeps it out of the
// binary.
package main
