package redact

import (
	"fmt"
	"math/rand/v2"
	"strings"
	"testing"
)

// literalStyles write PEM lines as string literals the way code embeds a
// key (#72): one literal per line joined by "+", adjacent literals, or one
// literal with "\n" escapes.
var literalStyles = map[string]func(lines []string) string{
	"go": func(lines []string) string {
		return "const k = \"\" +\n\t\"" + strings.Join(lines, "\\n\" +\n\t\"") + "\\n\"\n\nfunc f() {}\n"
	},
	"js": func(lines []string) string {
		return "const k =\n  '" + strings.Join(lines, "\\n' +\n  '") + "\\n';\nmodule.exports = k;\n"
	},
	"python": func(lines []string) string {
		return "KEY = (\n    \"" + strings.Join(lines, "\\n\"\n    \"") + "\\n\"\n)\n"
	},
	"java": func(lines []string) string {
		return "String k = \"\"\n        + \"" + strings.Join(lines, "\\r\\n\"\n        + \"") + "\";\n"
	},
	"json": func(lines []string) string {
		return "{\"type\": \"service_account\", \"private_key\": \"" + strings.Join(lines, "\\n") + "\\n\", \"id\": 1}\n"
	},
}

// A key body written as string literals, with no header or footer in the
// fragment, is masked in every style.
func TestRedactKeyBodyInLiterals(t *testing.T) {
	rng := rand.New(rand.NewPCG(41, 42))
	for name, style := range literalStyles {
		for _, width := range []int{64, 70, 76} {
			t.Run(fmt.Sprint(name, "/", width), func(t *testing.T) {
				body := fakeBody(rng, 600, width)
				assertNoBody(t, body, mustRedact(t, newRedactor(t), style(body)))
				two := body[:2]
				assertNoBody(t, two, mustRedact(t, newRedactor(t), style(two)))
			})
		}
	}
}

// arrayStyles write a key body as a one-line array of literals with no
// header or footer (#190 item 1).
var arrayStyles = map[string]func(lines []string) string{
	"go slice":     func(l []string) string { return `var k = []string{"` + strings.Join(l, `", "`) + `"}` },
	"js array":     func(l []string) string { return `const k = ['` + strings.Join(l, `','`) + `'];` },
	"python list":  func(l []string) string { return `K = ["` + strings.Join(l, `","`) + `"]` },
	"python tuple": func(l []string) string { return `K = ('` + strings.Join(l, `', '`) + `')` },
	"java array":   func(l []string) string { return `String[] k = {"` + strings.Join(l, `", "`) + `"};` },
	"escapes":      func(l []string) string { return `k := []string{"` + strings.Join(l, `\n", "`) + `\n"}` },
	// Near-miss separators (reviewer on #293).
	"go raw":       func(l []string) string { return "k := []string{`" + strings.Join(l, "`, `") + "`}" },
	"two blanks":   func(l []string) string { return `k := []string{"` + strings.Join(l, `",  "`) + `"}` },
	"tab":          func(l []string) string { return `k := []string{"` + strings.Join(l, "\",\t\"") + `"}` },
	"blank before": func(l []string) string { return `k := []string{"` + strings.Join(l, `" , "`) + `"}` },
	"concat":       func(l []string) string { return `k := "` + strings.Join(l, `" + "`) + `"` },
	"adjacent":     func(l []string) string { return `K = ("` + strings.Join(l, `" "`) + `")` },
	"bytes":        func(l []string) string { return `K = [b"` + strings.Join(l, `", b"`) + `"]` },
	"matlab":       func(l []string) string { return `k = ["` + strings.Join(l, `"; "`) + `"];` },
	"json string":  func(l []string) string { return `{"v": "[\"` + strings.Join(l, `\", \"`) + `\"]"}` },
}

// A header-less key body in a one-line literal array is masked by Redact
// and by File, alone and between lines of code.
func TestRedactKeyBodyInLiteralArray(t *testing.T) {
	rng := rand.New(rand.NewPCG(190, 1))
	for name, style := range arrayStyles {
		for _, width := range []int{64, 70, 76} {
			t.Run(fmt.Sprint(name, "/", width), func(t *testing.T) {
				body := fakeBody(rng, 1200, width)
				for _, text := range []string{style(body), "package x\n\n" + style(body) + "\n\nfunc f() {}\n", style(body[:2])} {
					assertNoBody(t, body, mustRedact(t, newRedactor(t), text))
					assertNoBody(t, body, mustFile(t, newRedactor(t), text))
				}
			})
		}
	}
}

// Ordinary string literals must not look like a key body.
func TestLiteralDetectorIgnoresCode(t *testing.T) {
	rng := rand.New(rand.NewPCG(43, 44))
	hex := fakeToken(rng, "0123456789abcdef", 64)
	samples := map[string]string{
		"prose concat":  "msg := \"the quick brown fox jumps over\\n\" +\n\t\"the lazy dog again and again\\n\" +\n\t\"and then it stops\\n\"\n",
		"prose escapes": "const usage = \"usage: creep scan [flags]\\n\\nflags:\\n  --record   write a run\\n  --replay   read a run\\n\"\n",
		"sql concat":    "q := \"SELECT id, name FROM users \" +\n\t\"WHERE id = $1 AND deleted_at IS NULL \" +\n\t\"ORDER BY created_at DESC\"\n",
		"hex digests":   "sums := \"" + hex + "\\n\" +\n\t\"" + hex + "\\n\"\n",
		"sri hashes":    "\"sha384-" + fakeToken(rng, base64Chars, 64) + "\" +\n\"sha384-" + fakeToken(rng, base64Chars, 64) + "\"\n",
		"data uri":      "img := \"data:image/png;base64," + fakeToken(rng, base64Chars, 70) + "\"\n",
		// One-line arrays split at each separator (#190) and stay unmasked.
		"prose array":    "words := []string{\"the quick brown fox jumps over the lazy dog\", \"pack my box with five dozen liquor jugs\"}\n",
		"sql array":      "qs := []string{\"SELECT id, name FROM users WHERE id = $1\", \"DELETE FROM sessions WHERE expires_at < now()\"}\n",
		"hex array":      "sums := []string{\"" + hex + "\", \"" + hex + "\", \"" + hex + "\"}\n",
		"path array":     "paths := ['internal/redact/pem_literal_test.go','internal/redact/pem.go','docs/architecture.md']\n",
		"sri array":      "integrity = [\"sha384-" + fakeToken(rng, base64Chars, 64) + "\", \"sha384-" + fakeToken(rng, base64Chars, 64) + "\"]\n",
		"sql one line":   "q := \"SELECT id, name, email FROM users WHERE id = $1 \" + \"AND deleted_at IS NULL ORDER BY created_at DESC\"\n",
		"prose adjacent": "msg = (\"the quick brown fox jumps over the lazy dog \" \"pack my box with five dozen liquor jugs\")\n",
		"hex concat":     "sum := \"" + hex + "\" + \"" + hex + "\"\n",
	}
	for name, text := range samples {
		if got := findPrivateKeys(text); len(got) > 0 {
			t.Errorf("%s: masked %q", name, text[got[0].start:got[0].end])
		}
	}
}

// Acceptance (#72): a key embedded as string literals, split at every byte
// into two calls, or into three with a middle of a given size, leaks no
// 8-byte window of its body from any call.
func TestRedactSplitLiteralKey(t *testing.T) {
	const shards = 4
	for name, style := range literalStyles {
		body := fakeBody(rand.New(rand.NewPCG(45, uint64(len(name)))), 500, 64)
		lines := append(append([]string{pemEdge("BEGIN", "RSA")}, body...), pemEdge("END", "RSA"))
		text := style(lines)
		set := windows(body)
		for shard := range shards {
			t.Run(fmt.Sprint(name, "/", shard), func(t *testing.T) {
				t.Parallel()
				for i := shard; i <= len(text); i += shards * offsetStep() {
					assertPartsHidden(t, set, text, i)
					for _, middle := range []int{160, 320} {
						assertPartsHidden(t, set, text, i, min(i+middle, len(text)))
					}
				}
			})
		}
	}
}

// assertPartsHidden redacts text cut at the given offsets, in order, on one
// Redactor, and fails if any output holds a window of the body.
func assertPartsHidden(t *testing.T, set map[string]bool, text string, cuts ...int) {
	t.Helper()
	r := newRedactor(t)
	from := 0
	for _, to := range append(cuts, len(text)) {
		if w := leakedWindow(set, mustRedact(t, r, text[from:to])); w != "" {
			t.Fatalf("cuts %v: part %d:%d leaked %q from %q", cuts, from, to, w, text[from:to])
		}
		from = to
	}
}
