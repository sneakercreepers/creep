//go:build race

package redact

// raceEnabled reports a -race build, which runs the regexp engine about 15
// times slower (issue #203).
const raceEnabled = true
