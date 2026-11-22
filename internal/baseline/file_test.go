package baseline

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/sneakercreepers/creep/internal/report"
)

// today is the tests' fixed clock.
var today = time.Date(2026, 11, 21, 15, 4, 5, 0, time.UTC)

const fp = "0123456789abcdef0123456789abcdef"

// fileWith is a baseline file holding entries, each a JSON object body.
func fileWith(entries ...string) string {
	for i, e := range entries {
		entries[i] = "{" + e + "}"
	}
	return `{"version": 1, "entries": [` + strings.Join(entries, ",") + `]}`
}

// entry is the body of a valid accepted entry with the fields of extra
// (`"key": value` pairs) put in place of its own or added: Parse refuses a
// repeated key, so a field cannot be overridden by repeating it.
func entry(extra string) string {
	return withFields(`"kind": "accepted", "fingerprint": "`+fp+`", "class": "sqli", "path": "app/db.py", "expires": "2027-01-01", "reason": "internal tool"`, extra)
}

// withFields returns the object body base with extra's fields set over it.
func withFields(base, extra string) string {
	fields := map[string]json.RawMessage{}
	for _, body := range []string{base, extra} {
		if err := json.Unmarshal([]byte("{"+body+"}"), &fields); err != nil {
			panic(fmt.Sprintf("test entry %q: %v", body, err))
		}
	}
	data, err := json.Marshal(fields)
	if err != nil {
		panic(err)
	}
	return strings.TrimSuffix(strings.TrimPrefix(string(data), "{"), "}")
}

// Hostile and malformed files fail whole (the caller exits 2): wildcards,
// traversal, far-future expiries, a missing reason, smuggled control text,
// unknown fields, trailing data and size bombs.
func TestBaselineFileRejectsHostile(t *testing.T) {
	many := make([]string, MaxEntries+1)
	for i := range many {
		many[i] = entry("")
	}
	tests := []struct {
		name string
		data string
		want string
	}{
		{"not JSON", "kind: accepted", "not the baseline JSON format"},
		{"empty", "", "not the baseline JSON format"},
		{"version 2", `{"version": 2, "entries": []}`, "version 2"},
		{"no version", `{"entries": []}`, "version 0"},
		{"unknown top field", `{"version": 1, "entries": [], "ignore_all": true}`, "not the baseline JSON format"},
		{"unknown entry field", fileWith(entry(`"match": "*"`)), "not the baseline JSON format"},
		{"key in another case", fileWith(entry(`"Kind": "baseline"`)), "unknown as spelled, or repeated"},
		{"top key in another case", `{"Version": 1, "entries": []}`, "unknown as spelled, or repeated"},
		{"repeated key", fileWith(entry("") + `, "expires": "2027-11-21"`), "unknown as spelled, or repeated"},
		{"repeated top key", `{"version": 1, "entries": [], "entries": [{` + entry("") + `}]}`, "unknown as spelled, or repeated"},
		{"trailing data", fileWith(entry("")) + `{"version": 1}`, "trailing data"},
		{"trailing garbage", fileWith(entry("")) + "x", "trailing data"},
		{"wildcard fingerprint", fileWith(entry(`"fingerprint": "*"`)), "fingerprint"},
		{"uppercase fingerprint", fileWith(entry(`"fingerprint": "` + strings.ToUpper(fp) + `"`)), "fingerprint"},
		{"short fingerprint", fileWith(entry(`"fingerprint": "0123"`)), "fingerprint"},
		{"wildcard class", fileWith(entry(`"class": "*"`)), "class"},
		{"empty class", fileWith(entry(`"class": ""`)), "class"},
		{"wildcard kind", fileWith(entry(`"kind": "*"`)), "kind"},
		{"traversal", fileWith(entry(`"path": "../../etc/passwd"`)), "path"},
		{"inner traversal", fileWith(entry(`"path": "app/../../x.py"`)), "path"},
		{"absolute path", fileWith(entry(`"path": "/etc/passwd"`)), "path"},
		{"drive letter", fileWith(entry(`"path": "C:/x.py"`)), "path"},
		{"backslash", fileWith(entry(`"path": "app\\db.py"`)), "path"},
		{"empty path", fileWith(entry(`"path": ""`)), "path"},
		{"dot path", fileWith(entry(`"path": "."`)), "path"},
		{"huge path", fileWith(entry(`"path": "` + strings.Repeat("a/", 2100) + `x"`)), "path"},
		{"no expiry", fileWith(`"kind": "baseline", "fingerprint": "` + fp + `", "class": "sqli", "path": "a.py"`), "expires"},
		{"bad date", fileWith(entry(`"expires": "2027-1-1"`)), "expires"},
		{"impossible date", fileWith(entry(`"expires": "2027-02-30"`)), "expires"},
		{"date with time", fileWith(entry(`"expires": "2027-01-01T00:00:00Z"`)), "expires"},
		{"far future", fileWith(entry(`"expires": "9999-12-31"`)), "more than 365 days"},
		{"one day past the cap", fileWith(entry(`"expires": "2027-11-23"`)), "more than 365 days"},
		{"accepted without reason", fileWith(entry(`"reason": ""`)), "reason"},
		{"blank reason", fileWith(entry(`"reason": "   "`)), "reason"},
		{"newline in reason", fileWith(entry(`"reason": "ok\nFAKE: suppressed nothing"`)), "reason"},
		{"escape in reason", fileWith(entry(`"reason": "ok\u001b[2K"`)), "reason"},
		{"bidi in reason", fileWith(entry(`"reason": "ok\u202egnp"`)), "reason"},
		{"long reason", fileWith(entry(`"reason": "` + strings.Repeat("x", report.MaxReasonBytes+1) + `"`)), "reason"},
		{"bad reason on baseline", fileWith(entry(`"kind": "baseline", "reason": "a\tb"`)), "reason"},
		{"too many entries", fileWith(many...), "4097 entries"},
		{"too large", fileWith(entry(`"reason": "` + strings.Repeat("x", MaxBytes) + `"`)), "larger than"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.data), today)
			if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Parse error %v, want ErrInvalid naming %q", err, tt.want)
			}
		})
	}
}

// Errors never quote a field's value: the file is the repository's.
func TestBaselineErrorsQuoteNoValue(t *testing.T) {
	_, err := Parse([]byte(fileWith(entry(`"path": "../\u001b]8;;http://evil/\u0007click"`))), today)
	if err == nil || strings.Contains(err.Error(), "evil") || strings.ContainsRune(err.Error(), 0x1b) {
		t.Fatalf("error %q quotes the hostile value", err)
	}
}

func TestParseAccepts(t *testing.T) {
	tests := []struct {
		name    string
		data    string
		entries int
	}{
		{"empty", `{"version": 1, "entries": []}`, 0},
		{"no entries key", `{"version": 1}`, 0},
		{"accepted", fileWith(entry("")), 1},
		{"baseline without reason", fileWith(entry(`"kind": "baseline", "reason": ""`)), 1},
		// An expired entry loads; Apply counts it and it suppresses nothing.
		{"past expiry", fileWith(entry(`"expires": "2020-01-01"`)), 1},
		{"at the cap with a day of clock slack", fileWith(entry(`"expires": "2027-11-22"`)), 1},
		{"duplicates count separately", fileWith(entry(""), entry("")), 2},
		{"path named like a glob is a plain name", fileWith(entry(`"path": "*"`)), 1},
		{"trailing whitespace", fileWith(entry("")) + "\n\n", 1},
		{"exactly the entry cap", fileWith(repeat(entry(""), MaxEntries)...), MaxEntries},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := Parse([]byte(tt.data), today)
			if err != nil || len(b.Entries) != tt.entries {
				t.Fatalf("Parse = %v, %v; want %d entries", b, err, tt.entries)
			}
		})
	}
}

func repeat(s string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = s
	}
	return out
}

// Marshal writes what Parse reads, in a fixed order.
func TestMarshalRoundTrip(t *testing.T) {
	in := &File{Version: Version, Entries: []Entry{
		{Kind: report.SuppressBaseline, Fingerprint: fp, Class: "ssrf", Path: "b.py", Expires: "2027-01-01"},
		{Kind: report.SuppressAccepted, Fingerprint: fp, Class: "sqli", Path: "a.py", Expires: "2027-01-01", Reason: "r"},
		{Kind: report.SuppressBaseline, Fingerprint: fp, Class: "sqli", Path: "a.py", Expires: "2027-01-01"},
	}}
	data, err := in.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	out, err := Parse(data, today)
	if err != nil {
		t.Fatal(err)
	}
	var order []string
	for _, e := range out.Entries {
		order = append(order, fmt.Sprintf("%s %s %s", e.Kind, e.Path, e.Class))
	}
	if got := strings.Join(order, ", "); got != "accepted a.py sqli, baseline a.py sqli, baseline b.py ssrf" {
		t.Errorf("order %s", got)
	}
	empty, err := (&File{Version: Version}).Marshal()
	if err != nil || !strings.Contains(string(empty), `"entries": []`) {
		t.Errorf("empty file %s, %v", empty, err)
	}
}
