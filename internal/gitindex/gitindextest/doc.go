// Package gitindextest writes git index files for tests.
//
// The parser in internal/gitindex and the vendor-tree tests in
// internal/cli both need indexes of every version, hash and flaw, built
// the way git builds them. Writing them here, independently of the parser,
// keeps one builder for both and checks the parser against the format,
// not against itself. Only _test.go files import it.
package gitindextest
