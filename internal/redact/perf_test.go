package redact

import (
	"io/fs"
	"os"
	"strings"
	"testing"
	"time"
)

func fill(unit string) string {
	return strings.Repeat(unit, MaxInputBytes/len(unit))
}

// largeInputs are near-misses for the detectors at the size cap: long runs
// of digits or word characters, "@" chains, common keywords, marker prefixes.
func largeInputs() map[string]string {
	return map[string]string{
		"code":       fill("func f(a int) string { return fmt.Sprintf(\"%d\", a) }\n"),
		"digits":     fill("4"),
		"word":       fill("a"),
		"at signs":   fill("a@"),
		"keywords":   fill("api_key = token secret password "),
		"markers":    fill("<SECRET_"),
		"hex kw":     fill("api_key=" + strings.Repeat("0123456789abcdef", 2) + " "),
		"passwords":  fill("password=x "),
		"subscripts": fill("x['api_key']['a'] = 'v' ['token"),
		"url creds":  fill("a://b:c@"),
		"aws 40":     "AKIA" + strings.Repeat("A", 16) + fill("Ab3/+")[20:],
		"key body":   fill(strings.Repeat("Ab3/+9x", 10)[:64] + "\n"),
		// Encoded separators run the URL-shaped rules a second time (#151).
		"json slashes": fill("discord" + ".com\\/api\\/webhooks\\/" + strings.Repeat("1", 18) + "\\/" + strings.Repeat("Ab3x", 11) + "\\/"),
		"percent":      fill("hooks.slack" + ".com%2Fservices%2F" + strings.Repeat("Ab3x", 12) + "%3a%2f"),
		"pem edges":    fill("-----BEGIN PRIV" + "ATE KEY-----\n-----END EC PRIV" + "ATE KEY-----\n"),
		// Long variable names give the generic rule's lazy 50-byte prefix a
		// match at every byte, each scanning the whole line again.
		"env keys": fill("SERVICE_ACCOUNT_PRIMARY_REGION_DEFAULT_SECONDARY_TOKEN=" + strings.Repeat("Ab3x", 30) + "\n"),
		// A format character after the start makes every detector run twice:
		// on the text and on its copy without them (#70).
		"format chars": fill("api_key = to" + zwsp + "ken secret pass" + zwsp + "word "),
	}
}

// everyKeyword wakes every rule, then pads with a word run: the slowest input
// found for the rule set, measured only by BenchmarkRedact.
func everyKeyword(tb testing.TB) string {
	head := keywordLines(tb)
	return head + fill("a")[len(head):]
}

// keywordLines holds every rule's keywords, one rule per line.
func keywordLines(tb testing.TB) string {
	rules, err := defaultRules()
	if err != nil {
		tb.Fatal(err)
	}
	var b strings.Builder
	for _, r := range rules {
		b.WriteString(strings.Join(r.keywords, " ") + "\n")
	}
	return b.String()
}

// withFormatChar puts a zero-width space in place of three bytes in the
// middle of text, keeping its length, so it takes both passes of
// withoutFormat: the worst case for its size.
func withFormatChar(text string) string {
	mid := len(text) / 2
	return text[:mid] + zwsp + text[mid+len(zwsp):]
}

// RE2 is linear, so these finish quickly. The bound is generous for slow CI
// runners and -race; it catches a quadratic regression, not small slowdowns.
func TestRedactLargeInputIsBounded(t *testing.T) {
	if testing.Short() {
		t.Skip("slow")
	}
	r := newRedactor(t)
	for name, text := range largeInputs() {
		start := time.Now()
		if _, err := r.Redact(text); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if d := time.Since(start); d > 30*time.Second {
			t.Errorf("%s: Redact of %d bytes took %s", name, len(text), d)
		}
	}
}

func BenchmarkRedact(b *testing.B) {
	inputs := largeInputs()
	inputs["every keyword"] = everyKeyword(b)
	inputs["every keyword, format char"] = withFormatChar(everyKeyword(b))
	// Kept references read the literals after them once per line (#71): one
	// line of them, and lines of lookups with a default.
	inputs["references"] = fill(`password = None or "ab" `)
	inputs["lookups"] = fill(`secret = os.environ.get("X", "default-value")` + "\n")
	r := newRedactor(b)
	for name, text := range inputs {
		b.Run(name, func(b *testing.B) {
			b.SetBytes(int64(len(text)))
			for b.Loop() {
				if _, err := r.Redact(text); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// repoChunks cuts the repository's own Go sources into chunks of at most
// MaxInputBytes, split at line ends: real code, the common input.
func repoChunks(tb testing.TB) []string {
	tb.Helper()
	var chunks []string
	var cur strings.Builder
	// A root-scoped walk cannot follow a symlink out of the repository.
	root, err := os.OpenRoot("../..")
	if err != nil {
		tb.Fatal(err)
	}
	defer root.Close()
	repo := root.FS()
	err = fs.WalkDir(repo, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") {
			return err
		}
		data, err := fs.ReadFile(repo, path)
		for _, line := range strings.SplitAfter(string(data), "\n") {
			if cur.Len()+len(line) > MaxInputBytes {
				chunks = append(chunks, cur.String())
				cur.Reset()
			}
			cur.WriteString(line)
		}
		return err
	})
	if err != nil {
		tb.Fatal(err)
	}
	return append(chunks, cur.String())
}

// BenchmarkRedactRepoCode measures the ordinary case: the repository's own
// code in full-size chunks.
func BenchmarkRedactRepoCode(b *testing.B) {
	chunks := repoChunks(b)
	r := newRedactor(b)
	for b.Loop() {
		for _, c := range chunks {
			if _, err := r.Redact(c); err != nil {
				b.Fatal(err)
			}
		}
	}
}
