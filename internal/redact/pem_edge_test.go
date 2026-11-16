package redact

import (
	"fmt"
	"math/rand/v2"
	"strings"
	"testing"
)

// Acceptance (#73): the issue's repro, a full body line between code and a
// cut footer, is masked.
func TestRedactBodyBeforeCutFooter(t *testing.T) {
	full := strings.Repeat("Ab3/+9xQ", 8)
	last := "aZcli0FKZmoDX00puJKaNukbliI+bw=="
	text := "\n" + full + "\n" + last + "\n-----END RSA PRIV"
	out := mustRedact(t, newRedactor(t), text)
	assertNoBody(t, []string{full, last}, out)
}

// Body lines next to a header or footer stub are masked, even alone and
// shorter than 40 bytes; a few dashes in code do not mask a word.
func TestCutEdgeStubs(t *testing.T) {
	rng := rand.New(rand.NewPCG(51, 52))
	full := fakeToken(rng, base64Chars, 64)
	short := fakeToken(rng, base64Chars, 22) + "=="
	tests := []struct {
		name   string
		text   string
		hidden []string // must not leak
		kept   string   // must stay unchanged; "" when hidden is set
	}{
		{"short line before footer stub", "func f() {}\n" + short + "\n-----END RSA PRIV", []string{short}, ""},
		{"short line before bare END", "x := 1\n" + short + "\n-----END", []string{short}, ""},
		{"full and short before dashes", "x := 1\n" + full + "\n" + short + "\n--", []string{full, short}, ""},
		{"full line before one dash", "x := 1\n" + full + "\n-", []string{full}, ""},
		{"partial, full, short, stub", short[:9] + "\n" + full + "\n" + short + "\n-----END OPENSSH PRIVATE KE", []string{full, short}, ""},
		{"literal footer stub", "x := 1 +\n\t\"" + full + "\\n\" +\n\t\"" + short + "\\n\" +\n\t\"-----EN", []string{full, short}, ""},
		{"json footer stub", `{"k": "x\n` + full + `\n` + short + `\n-----END PRIVATE`, []string{full, short}, ""},
		{"lowercase footer stub", "x\n" + short + "\n-----end rsa", []string{short}, ""},
		{"short line after header stub", "ATE KEY-----\n" + short + "\n-----", []string{short}, ""},
		{"full line after header stub", "Y-----\n" + full + "\n" + short + "\nfunc f() {}\n", []string{full, short}, ""},
		{"full line after dashes", "--\n" + full + "\nfunc f() {}\n", []string{full}, ""},
		{"literal header stub", "KEY-----\\n\" +\n\t\"" + short + "\\n\" +\n\tx\n", []string{short}, ""},
		{"word before dash", "func f() {\n\treturn\n-", nil, "func f() {\n\treturn\n-"},
		{"word before dashes", "x--\n\treturn\n---", nil, "x--\n\treturn\n---"},
		{"word after hr", "------\nIntroduction\nmore text here\n", nil, "------\nIntroduction\nmore text here\n"},
		{"stub not at end", "x\n" + short + "\n-----END RSA PRIV\n", nil, "x\n" + short + "\n-----END RSA PRIV\n"},
		{"prose before stub", "x\nsome words here\n-----END", nil, "x\nsome words here\n-----END"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out := mustRedact(t, newRedactor(t), tc.text)
			if tc.hidden != nil {
				assertNoBody(t, tc.hidden, out)
				return
			}
			if out != tc.kept {
				t.Fatalf("changed %q to %q", tc.kept, out)
			}
		})
	}
}

// Acceptance (#73): every window of 40 to 600 bytes of a key in code, at
// every offset, redacted in one to three calls on one Redactor, leaks no full
// body line.
func TestRedactKeyWindowsInCalls(t *testing.T) {
	const shards = 8
	key, body := fakeKey(rand.New(rand.NewPCG(53, 54)), "RSA", 700, 64)
	text := "func f() {}\n\nconst k = `" + key + "`\n\nfunc g() {}\n"
	full := body[:len(body)-1]
	for shard := range shards {
		t.Run(fmt.Sprint(shard), func(t *testing.T) {
			t.Parallel()
			for size := 40 + 20*shard; size <= 600; size += 20 * shards {
				for i := 0; i+size <= len(text); i += offsetStep() {
					for calls := 1; calls <= 3; calls++ {
						assertNoFullLine(t, full, text[i:i+size], calls)
					}
				}
			}
		})
	}
}

// assertNoFullLine redacts window in calls equal parts on one Redactor.
func assertNoFullLine(t *testing.T, full []string, window string, calls int) {
	t.Helper()
	r := newRedactor(t)
	step := len(window) / calls
	for c := range calls {
		end := (c + 1) * step
		if c == calls-1 {
			end = len(window)
		}
		part := window[c*step : end]
		out := mustRedact(t, r, part)
		for _, line := range full {
			if strings.Contains(out, line) {
				t.Fatalf("%d calls: part %q leaked line %q", calls, part, line)
			}
		}
	}
}
