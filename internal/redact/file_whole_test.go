package redact

import (
	"math/rand/v2"
	"strings"
	"testing"
)

// fillerLine wakes no detector, so the only markers in a file are the doc's.
const fillerLine = "total := compute(left, right)\n"

// acrossCut returns filler, doc and filler with the head sized so that no
// chunk holds doc from its start through the last copy of secret: the case
// the chunk overlap alone cannot cover.
func acrossCut(t *testing.T, doc, secret string) (head, tail string) {
	t.Helper()
	tail = strings.Repeat(fillerLine, MaxInputBytes/len(fillerLine))
	end := strings.LastIndex(doc, secret) + len(secret)
	for n := (MaxInputBytes - len(doc)) / len(fillerLine); n*len(fillerLine) < MaxInputBytes; n++ {
		head = strings.Repeat(fillerLine, n)
		if !heldByOneChunk(head+doc+tail, len(head), len(head)+end) {
			return head, tail
		}
	}
	t.Fatal("no head length puts a chunk cut inside the doc")
	return "", ""
}

func heldByOneChunk(text string, start, end int) bool {
	for _, c := range chunkBounds(text) {
		if c.start <= start && end <= c.end {
			return true
		}
	}
	return false
}

// blanks is n bytes of empty lines.
func blanks(n int) string { return strings.Repeat("\n", n) }

// wholeFileDocs reach further back than chunkOverlap, through a long
// continuation line or a run of blank lines (issue #70). The secrets avoid
// key names the password and generic detectors know, so only the rule that
// File must run over the whole file can mask them. Secrets are random and
// keywords split, so the repository's own gitleaks job sees no credential.
func wholeFileDocs(rng *rand.Rand) map[string]struct{ doc, secret string } {
	curl := "cu" + "rl https://api.example.test/v1/items \\\n  -d '" + strings.Repeat("a", 4600) + "' \\\n"
	user, bearer := fakeToken(rng, alnum, 12), fakeToken(rng, alnum, 16)
	b64 := fakeToken(rng, "abcdefghijklmnopqrstuvwxyz0123456789", 24)
	sk := "sk" + "_" + fakeToken(rng, alnum, 29)
	nuget := fakeToken(rng, alnum, 12)
	secret := "kind: Sec" + "ret\nmetadata:\n  name: db\ndata:"
	jwtBody := fakeToken(rng, alnum, 15)
	return map[string]struct{ doc, secret string }{
		"curl user after a long payload":   {curl + "  -u admin:" + user + "\n", user},
		"curl header after a long payload": {curl + "  -H 'Author" + "ization: Bearer " + bearer + "'\n", bearer},
		"k8s blanks between key and value": {"apiVersion: v1\n" + secret + "\n  connection: |" + blanks(5000) + "    " + b64 + "==\n", b64},
		"k8s blanks between data and key":  {"apiVersion: v1\n" + secret + blanks(5000) + "  connection: " + b64 + "==\n", b64},
		"freemius blanks before value":     {"<?php\n$config = array(\n  'secret" + "_key' =>" + blanks(5000) + "  '" + sk + "',\n);\n", sk},
		"nuget blanks before value": {
			"<configuration>\n  <add key=\"ClearText" + "Password\"" + blanks(5000) + "  value=\"" + nuget + "\" />\n</configuration>\n",
			nuget,
		},
		"base64 JWT wrapped at 100 columns": {
			"token:\n" + wrap("ZXlK"+"aGJHY2lPaUpJVXpJMU5pSjk"+strings.Repeat(jwtBody, 340), 100) +
				"\n# The token class takes in newlines and words; this line ends it.\n",
			jwtBody,
		},
	}
}

// wrap cuts s into lines of n bytes.
func wrap(s string, n int) string {
	var b strings.Builder
	for len(s) > n {
		b.WriteString(s[:n] + "\n")
		s = s[n:]
	}
	b.WriteString(s)
	return b.String()
}

// TestFileMasksAcrossCutAsRedact: a doc that no chunk holds whole is masked
// by File exactly as Redact masks the doc alone, and its secret is gone.
func TestFileMasksAcrossCutAsRedact(t *testing.T) {
	for name, tc := range wholeFileDocs(rand.New(rand.NewPCG(73, 73))) {
		t.Run(name, func(t *testing.T) {
			alone := mustRedact(t, newRedactor(t), tc.doc)
			if strings.Contains(alone, tc.secret) {
				t.Fatalf("Redact leaves %q in the doc alone: the case is broken", tc.secret)
			}
			head, tail := acrossCut(t, tc.doc, tc.secret)
			r := newRedactor(t)
			out := mustFile(t, r, head+tc.doc+tail)
			if out != head+alone+tail {
				t.Errorf("File masks the doc across a chunk cut unlike Redact; secret visible: %v",
					strings.Contains(out, tc.secret))
			}
			if r.Unredact(out) != head+tc.doc+tail {
				t.Error("Unredact(File(x)) != x")
			}
		})
	}
}
