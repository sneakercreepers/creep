package discover

import (
	"strings"
	"testing"
)

// Every row of the shipped table matches its own fixture line with its
// kind, and the table stays within ADR 0017's limits.
func TestTripwireRowsMatchFixtures(t *testing.T) {
	rows, err := loadTripwire()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) > maxTripwireRows {
		t.Fatalf("%d rows, cap %d", len(rows), maxTripwireRows)
	}
	kinds := map[SinkKind]bool{}
	for _, r := range rows {
		kinds[r.kind] = true
		if !r.matches([]byte(r.fixture)) {
			t.Errorf("row %s %q does not match its fixture %q", r.kind, r.token, r.fixture)
		}
		hits, _ := tripwire(rows, []byte(r.fixture))
		if !containsHit(hits, 1, r.kind) {
			t.Errorf("fixture %q gives %+v, want a %s hit", r.fixture, hits, r.kind)
		}
	}
	for _, k := range sinkKinds {
		if !kinds[k.kind] {
			t.Errorf("no row for kind %s", k.name)
		}
	}
}

func containsHit(hits []hit, line uint32, kind SinkKind) bool {
	for _, h := range hits {
		if h.line == line && h.kind == kind {
			return true
		}
	}
	return false
}

// F7: the identifier rule applies only to signatures that start with an
// identifier byte; one that starts with punctuation, like ".raw(", matches
// after any byte.
func TestSignatureBoundary(t *testing.T) {
	tests := []struct {
		token, line string
		want        bool
	}{
		{"open(", "f = open(p)", true},
		{"open(", "open(p)", true},
		{"open(", "fopen(p)", false},
		{"open(", "fopen(p); open(q)", true},
		{"open(", "_open(p)", false},
		{"open(", "x9open(p)", false},
		{"open(", "os.open(p)", true},
		{"execute(", "cursor.execute(q)", true},
		{"execute(", "reexecute(q)", false},
		{".raw(", "User.objects.raw(q)", true},
		{".raw(", "x.raw(q)", true},
		{".raw(", ".raw(q)", true},
		{".raw(", "x.rawish(q)", false},
		{"$where", "{ $where: f }", true},
		{"$where", "x$where", true},
		{"%x(", "o = %x(ls)", true},
	}
	for _, tt := range tests {
		s, err := parseSignature("sql\t" + tt.token + "\tfixture")
		if err != nil {
			t.Fatal(err)
		}
		if got := s.matches([]byte(tt.line)); got != tt.want {
			t.Errorf("%q in %q = %v, want %v", tt.token, tt.line, got, tt.want)
		}
	}
}

func TestTripwireLinesAndCap(t *testing.T) {
	rows, err := loadTripwire()
	if err != nil {
		t.Fatal(err)
	}
	text := "x = 1\r\nos.system(a); subprocess.run(b)\n\nrequests.get(u); open(f)\nlast = eval(x)"
	hits, cut := tripwire(rows, []byte(text))
	want := []hit{{2, SinkShell}, {4, SinkFile}, {4, SinkHTTPClient}, {5, SinkShell}}
	if cut || !sameHits(hits, want) {
		t.Errorf("hits = %+v cut %v, want %+v", hits, cut, want)
	}
	flood := strings.Repeat("os.system(x)\n", MaxTripwireHits+1)
	hits, cut = tripwire(rows, []byte(flood))
	if !cut || len(hits) != MaxTripwireHits {
		t.Errorf("%d hits, cut %v; want the cap and cut", len(hits), cut)
	}
	hits, cut = tripwire(rows, []byte(strings.Repeat("os.system(x)\n", MaxTripwireHits)))
	if cut || len(hits) != MaxTripwireHits {
		t.Errorf("%d hits, cut %v at exactly the cap; want no cut", len(hits), cut)
	}
}

func sameHits(got, want []hit) bool {
	if len(got) != len(want) {
		return false
	}
	for _, w := range want {
		if !containsHit(got, w.line, w.kind) {
			return false
		}
	}
	return true
}

func TestParseTripwireRejects(t *testing.T) {
	for _, data := range []string{
		"",
		"sql\texecute(",
		"xss\tinnerHTML\tel.innerHTML = x",
		"sql\tx\tx",
		"sql\t" + strings.Repeat("a", maxSignatureBytes+1) + "\tfixture",
		strings.Repeat("sql\texecute(\tcursor.execute(q)\n", maxTripwireRows+1),
	} {
		if _, err := parseTripwire(data); err == nil {
			t.Errorf("parseTripwire(%.40q) accepted a broken table", data)
		}
	}
}

// BenchmarkTripwire measures the documented worst case: a file at
// redact.MaxFileBytes. Short lines dense with near-misses make every row
// search every line; one long line of repeated near-misses makes the
// bounded signatures resume after each occurrence.
func BenchmarkTripwire(b *testing.B) {
	rows, err := loadTripwire()
	if err != nil {
		b.Fatal(err)
	}
	shapes := map[string][]byte{
		"short lines": fill("fopen(x) reexecute(y) xspawn(z)\n"),
		"one line":    fill("xopen(xexec(xeval(xsystem("),
		"code":        fill("    rows = db.execute(query).fetchall()\n"),
	}
	for name, text := range shapes {
		b.Run(name, func(b *testing.B) {
			b.SetBytes(int64(len(text)))
			for b.Loop() {
				tripwire(rows, text)
			}
		})
	}
}

func fill(unit string) []byte {
	return []byte(strings.Repeat(unit, (1<<20)/len(unit)))
}
