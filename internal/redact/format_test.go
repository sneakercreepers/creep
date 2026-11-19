package redact

import (
	"math/rand/v2"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"
)

// ch spells a character by code point, so this file holds no invisible one.
func ch(codes ...rune) string { return string(codes) }

var (
	zwsp = ch(0x200b)
	zwj  = ch(0x200d)
	bom  = ch(0xfeff)
)

// formatChars are format characters (Unicode Cf) that render as nothing.
var formatChars = map[string]string{
	"zero-width space":       zwsp,
	"zero-width non-joiner":  ch(0x200c),
	"zero-width joiner":      zwj,
	"word joiner":            ch(0x2060),
	"byte order mark":        bom,
	"soft hyphen":            ch(0x00ad),
	"right-to-left override": ch(0x202e),
	"mongolian vowel sep":    ch(0x180e),
	"tag latin a":            ch(0xe0041),
}

var oneMarkerRe = regexp.MustCompile(`^<SECRET_[A-Z0-9_]+_[0-9]+>$`)

// splitAt inserts mark into s after n bytes.
func splitAt(s string, n int, mark string) string { return s[:n] + mark + s[n:] }

// assertMaskedExactly checks that out is text with text[a:b] replaced by one
// marker: every byte of the token, format characters included, is covered,
// and nothing else changed.
func assertMaskedExactly(t *testing.T, out, text string, a, b int) {
	t.Helper()
	tail := len(text) - b
	if len(out) < a+tail || out[:a] != text[:a] || out[len(out)-tail:] != text[b:] {
		t.Fatalf("output changed bytes outside the token:\n out %q\ntext %q", out, text)
	}
	if m := out[a : len(out)-tail]; !oneMarkerRe.MatchString(m) {
		t.Fatalf("token bytes %q replaced by %q, want one marker", text[a:b], m)
	}
}

// formatTokens build a line and the bounds of the token it holds, with mark
// placed where it hides the token from the rules.
var formatTokens = map[string]func(rng *rand.Rand, mark string) (line string, a, b int){
	"inside the prefix": func(rng *rand.Rand, mark string) (string, int, int) {
		pat := splitAt(fakeGitHub(rng), 2, mark)
		return "token := \"" + pat + "\"\n", 10, 10 + len(pat)
	},
	"inside the body": func(rng *rand.Rand, mark string) (string, int, int) {
		pat := splitAt(fakeGitHub(rng), 20, mark)
		return "token := \"" + pat + "\"\n", 10, 10 + len(pat)
	},
	"twice": func(rng *rand.Rand, mark string) (string, int, int) {
		pat := splitAt(splitAt(fakeGitHub(rng), 30, mark), 3, mark+mark)
		return "x = " + pat + "\n", 4, 4 + len(pat)
	},
	"inside an AWS key id": func(rng *rand.Rand, mark string) (string, int, int) {
		id := splitAt(fakeAWS(rng), 4, mark)
		return "id: " + id + "\n", 4, 4 + len(id)
	},
	"inside the key name": func(rng *rand.Rand, mark string) (string, int, int) {
		// The "!" keeps the Terraform password rule, which masks the
		// quotes too, out of it: only the password detector masks the value.
		pw := splitAt(fakePassword(rng), 4, "!")
		line := "pass" + mark + "word = \"" + pw + "\"\n"
		a := strings.Index(line, pw)
		return line, a, a + len(pw)
	},
}

// TestFormatCharInsideTokenIsMasked covers issue #70: a format character
// inside a token, its prefix or its key name no longer hides it, from Redact
// or File, and the mask covers every byte of the token, format characters
// included, while the text around it is sent unchanged.
func TestFormatCharInsideTokenIsMasked(t *testing.T) {
	rng := rand.New(rand.NewPCG(70, 70))
	for charName, mark := range formatChars {
		for shape, build := range formatTokens {
			t.Run(charName+"/"+shape, func(t *testing.T) {
				line, a, b := build(rng, mark)
				text := "func f() {\n" + line + "}\n"
				a, b = a+11, b+11
				r := newRedactor(t)
				out := mustRedact(t, r, text)
				assertMaskedExactly(t, out, text, a, b)
				if r.Unredact(out) != text {
					t.Fatal("Unredact(Redact(x)) != x")
				}
				assertMaskedExactly(t, mustFile(t, newRedactor(t), text), text, a, b)
			})
		}
	}
}

// TestFormatCharKeepsOriginalMatches: removing a format character joins its
// neighbors, so a token followed by one and a word would lose its boundary
// in the copy alone; the original is searched too. A leading byte order mark
// is skipped and kept in the output.
func TestFormatCharKeepsOriginalMatches(t *testing.T) {
	rng := rand.New(rand.NewPCG(71, 71))
	id := fakeAWS(rng)
	pat := fakeGitHub(rng)
	tests := map[string]struct {
		text, token string
	}{
		"key id then a joined word": {"id: " + id + zwsp + "next\n", id},
		"byte order mark first":     {bom + "token := \"" + pat + "\"\n", pat},
		"marks first and later":     {bom + zwsp + "x" + zwsp + " = 1\ntoken := \"" + pat + "\"\n", pat},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			a := strings.Index(tc.text, tc.token)
			assertMaskedExactly(t, mustRedact(t, newRedactor(t), tc.text), tc.text, a, a+len(tc.token))
			assertMaskedExactly(t, mustFile(t, newRedactor(t), tc.text), tc.text, a, a+len(tc.token))
		})
	}
}

// TestFormatCharOrdinaryTextUnchanged guards against false positives (#71):
// emoji sequences, Persian text, soft hyphens and bidi marks are sent as
// they are.
func TestFormatCharOrdinaryTextUnchanged(t *testing.T) {
	texts := []string{
		"// family: " + ch(0x1f468, 0x200d, 0x1f469, 0x200d, 0x1f467) + "\n",
		"msg = \"" + ch(0x0645, 0x06cc, 0x200c, 0x062e, 0x0648, 0x0627, 0x0647, 0x0645) + "\"\n",
		"<p>extra" + ch(0x00ad) + "ordinary</p>\n",
		"label = \"" + ch(0x202b) + "shalom" + ch(0x202c) + "\"\n",
		bom + "package main\n\nfunc main() {}\n",
	}
	for _, text := range texts {
		if out := mustRedact(t, newRedactor(t), text); out != text {
			t.Errorf("Redact(%q) = %q, want it unchanged", text, out)
		}
		if out := mustFile(t, newRedactor(t), text); out != text {
			t.Errorf("File(%q) = %q, want it unchanged", text, out)
		}
	}
}

// TestFormatCharValueRemembered: a value masked with a format character in it
// is re-masked later without one, and a value masked plainly is re-masked
// later with one inside, where no rule matches it any more.
func TestFormatCharValueRemembered(t *testing.T) {
	rng := rand.New(rand.NewPCG(72, 72))
	pw := fakePassword(rng)
	split := splitAt(pw, 6, zwsp)
	tests := map[string]struct{ first, later, value string }{
		"split first, plain later": {"password = \"" + split + "\"\n", "login(\"" + pw + "\")\n", pw},
		"plain first, split later": {"password = \"" + pw + "\"\n", "login(\"" + split + "\")\n", split},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := newRedactor(t)
			mustRedact(t, r, tc.first)
			a := strings.Index(tc.later, tc.value)
			assertMaskedExactly(t, mustRedact(t, r, tc.later), tc.later, a, a+len(tc.value))
		})
	}
}

func TestStripFormatOffsets(t *testing.T) {
	tests := []struct {
		text, want string
	}{
		{"", ""},
		{"abc", "abc"},
		{"a" + zwsp + "b", "ab"},
		{zwsp + zwj, ""},
		{"\xffa" + ch(0x00ad) + "b\xe2\x80", "\xffab\xe2\x80"},
		{ch(0xe9, 0x200b, 0xe9), ch(0xe9, 0xe9)},
	}
	for _, tc := range tests {
		got, offsets := stripFormat(tc.text)
		if got != tc.want || len(offsets) != len(got) {
			t.Fatalf("stripFormat(%q) = %q with %d offsets, want %q", tc.text, got, len(offsets), tc.want)
		}
		for i := range got {
			if tc.text[offsets[i]] != got[i] {
				t.Errorf("stripFormat(%q): byte %d maps to %d", tc.text, i, offsets[i])
			}
		}
		if hasFormat(tc.text) != (got != tc.text) {
			t.Errorf("hasFormat(%q) = %v", tc.text, hasFormat(tc.text))
		}
	}
}

// FuzzFormatInsideSecret puts a format character at a byte offset the fuzzer
// picks (moved to a rune start) inside a random secret: the secret never
// shows in the output, even once the format characters are taken out, and
// Redact stays reversible.
func FuzzFormatInsideSecret(f *testing.F) {
	f.Add(uint64(1), uint8(0), uint16(3), zwsp)
	f.Add(uint64(2), uint8(1), uint16(1), bom)
	f.Add(uint64(3), uint8(4), uint16(9), ch(0x00ad, 0x2060))
	f.Add(uint64(4), uint8(13), uint16(40), ch(0xe0020))
	f.Fuzz(func(t *testing.T, seed uint64, kind uint8, at uint16, mark string) {
		if mark == "" || !utf8.ValidString(mark) || strings.ContainsFunc(mark, func(r rune) bool { return !isFormat(r) }) {
			t.Skip("mark must be format characters only")
		}
		rng := rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))
		line, secret := fakeLine(rng, int(kind)%(len(secretMakers)+len(credentialMakers)))
		n := int(at) % (len(secret) + 1)
		for n > 0 && !utf8.RuneStart(secret[n%len(secret)]) {
			n--
		}
		split := splitAt(secret, n, mark)
		text := "x := 1\n" + strings.Replace(line, secret, split, 1) + "\ny := 2\n"
		r := newRedactor(t)
		out := mustRedact(t, r, text)
		if clean, _ := stripFormat(out); strings.Contains(out, split) || strings.Contains(clean, secret) {
			t.Fatalf("secret leaked\nsecret %q\noutput %q", split, out)
		}
		if r.Unredact(out) != text {
			t.Fatal("Unredact(Redact(x)) != x")
		}
	})
}
