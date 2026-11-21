//go:build !race

package redact

// raceEnabled reports a -race build, which runs the regexp engine 18 to 28
// times slower (measured on #206).
const raceEnabled = false
