package redact

import (
	"strings"
	"testing"
)

// fillFile repeats unit up to MaxFileBytes, the size File runs
// findPrivateKeys over in one pass.
func fillFile(unit string) string {
	return strings.Repeat(unit, MaxFileBytes/len(unit))
}

// privateKeyWorstCases are the shapes that cost findPrivateKeys the most per
// byte (#190): every split it makes inside a line is one more body line to
// judge.
func privateKeyWorstCases() map[string]string {
	body := strings.Repeat("Ab3/+9x", 10)[:64]
	return map[string]string{
		// The tester's case on #184: a "\n" escape on every other line.
		"escape every other line": fillFile("\t\"" + body + "\\n\" +\n\tx := f(a, b)\n"),
		// One-line literal arrays split at each separator, like "\n" escapes.
		"literal arrays": fillFile("k := []string{\"" + strings.Repeat(body+"\", \"", 60) + body + "\"}\n"),
		// The densest splits: a separator every five bytes.
		"separators": fillFile("x := []string{" + strings.Repeat(`"a", `, 600) + "\"a\"}\n"),
		// Adjacent literals split every four bytes; a near miss reads the
		// most bytes a separator may hold before it fails (reviewer on #293).
		"adjacent":  fillFile("x := (" + strings.Repeat(`"a" `, 600) + "\"a\")\n"),
		"near miss": fillFile("x := " + strings.Repeat(`"    ,    bbx`, 300) + "\n"),
	}
}

// BenchmarkPrivateKeysRepoCode is the ordinary case: findPrivateKeys over a
// whole file of the repository's own code (#190, §8).
func BenchmarkPrivateKeysRepoCode(b *testing.B) {
	benchPrivateKeys(b, repoCode(b, MaxFileBytes))
}

// BenchmarkPrivateKeysWorstCase backs the documented worst case: the
// split-heavy shapes stay linear and within a small multiple of repo code.
func BenchmarkPrivateKeysWorstCase(b *testing.B) {
	for name, text := range privateKeyWorstCases() {
		b.Run(name, func(b *testing.B) { benchPrivateKeys(b, text) })
	}
}

func benchPrivateKeys(b *testing.B, text string) {
	b.SetBytes(int64(len(text)))
	for b.Loop() {
		findPrivateKeys(text)
	}
}
