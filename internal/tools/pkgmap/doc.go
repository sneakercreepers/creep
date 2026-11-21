// Command pkgmap writes docs/map.md, the package map that agents and
// contributors read instead of exploring the tree.
//
// It lists every package `go list ./...` reports for any release platform
// in .goreleaser.yaml, with cgo off, so the map is the same on every host
// (#117), with the first sentence of the package comment in its doc.go and
// its layer from the layers block in docs/architecture.md §3. go list already leaves out testdata, directories
// whose names start with "." or "_" (so .claude/ and the agent worktrees in
// it) and nested modules. A package without a doc.go, a doc.go without a
// package comment, or a package with no row in the layers table is an error,
// so the map can never skip a package quietly.
//
// `make map` writes the file. `make check` runs it with -check, which fails
// when docs/map.md differs from what it would write, so adding, removing or
// renaming a package, or changing the first sentence of a doc.go, fails CI
// until the map is regenerated.
//
// It is stdlib-only build tooling; the layers table (internal/tools/*) keeps
// it out of the binary.
package main
