package baseline

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite testdata/moves/fingerprints.golden")

// sinkLines returns the lines of a fixture marked as a sink ("# sink:
// <class>"), keyed by class, as redact.File would hand them over.
func sinkLines(t *testing.T, name string) map[string]string {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", "moves", name))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	out := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if _, class, ok := strings.Cut(sc.Text(), "# sink: "); ok {
			out[class] = sc.Text()
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func fixtureFingerprints(t *testing.T, name string) string {
	t.Helper()
	lines := sinkLines(t, name)
	var b strings.Builder
	for _, class := range []string{"sqli", "command_injection", "path_traversal"} {
		line, ok := lines[class]
		if !ok {
			t.Fatalf("%s: no sink for %s", name, class)
		}
		fmt.Fprintf(&b, "%s %s\n", class, Fingerprint(class, "app/views.py", SinkAnchor(line)))
	}
	return b.String()
}

// Acceptance (#27): fingerprints survive unrelated code moves. after.py is
// before.py with code added above and between the sinks, a sink moved
// below another, its lines reindented, and its markers numbered as a run
// that met other secrets first would number them. Both give the committed
// fingerprints, so a change to the algorithm (which would break every
// committed baseline) fails here too.
func TestFingerprintGolden(t *testing.T) {
	golden := filepath.Join("testdata", "moves", "fingerprints.golden")
	before := fixtureFingerprints(t, "before.py")
	if *update {
		if err := os.WriteFile(golden, []byte(before), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"before.py", "after.py"} {
		if got := fixtureFingerprints(t, name); got != string(want) {
			t.Errorf("%s fingerprints:\n%s\nwant (golden):\n%s", name, got, want)
		}
	}
}

// What makes a finding new: its class, its path or its sink line changing.
func TestFingerprintChanges(t *testing.T) {
	base := Fingerprint("sqli", "app/db.py", SinkAnchor(`cur.execute("SELECT " + q)`))
	tests := []struct {
		name       string
		class      string
		path       string
		anchor     string
		wantSame   bool
		wantLength int
	}{
		{"same line, other spacing", "sqli", "app/db.py", SinkAnchor("\t  cur.execute(\"SELECT \"   +  q)  "), true, 32},
		{"another class", "command_injection", "app/db.py", SinkAnchor(`cur.execute("SELECT " + q)`), false, 32},
		{"another file", "sqli", "app/other.py", SinkAnchor(`cur.execute("SELECT " + q)`), false, 32},
		{"sink line edited", "sqli", "app/db.py", SinkAnchor(`cur.execute("SELECT * " + q)`), false, 32},
		{"scanner anchor never equals code", "sqli", "app/db.py", ScannerAnchor(`cur.execute("SELECT " + q)`), false, 32},
		// Length prefixes: moving a separator between fields changes the hash.
		{"field boundary shifted", "sqli", "app/db.pyc", SinkAnchor(`ur.execute("SELECT " + q)`), false, 32},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Fingerprint(tt.class, tt.path, tt.anchor)
			if (got == base) != tt.wantSame || len(got) != tt.wantLength {
				t.Errorf("fingerprint %s vs %s: same %v, want %v", got, base, got == base, tt.wantSame)
			}
		})
	}
}

// The anchor drops only a marker's run counter: the label stays, escaped
// marker-like repository text stays literal, and other text is untouched.
func TestSinkAnchor(t *testing.T) {
	tests := []struct {
		line string
		want string
	}{
		{`key = "<SECRET_AWS_ACCESS_TOKEN_12>"`, `code:key = "<SECRET_AWS_ACCESS_TOKEN>"`},
		{`send(<PII_EMAIL_1>, <PII_EMAIL_2>)`, `code:send(<PII_EMAIL>, <PII_EMAIL>)`},
		{`x = "<ESC_SECRET_X_1>"`, `code:x = "<ESC_SECRET_X_1>"`},
		{`v = "<SECRET_X>"`, `code:v = "<SECRET_X>"`},
		{"\t\tos.system(cmd)   # run", "code:os.system(cmd) # run"},
		{"", "code:"},
	}
	for _, tt := range tests {
		if got := SinkAnchor(tt.line); got != tt.want {
			t.Errorf("SinkAnchor(%q) = %q, want %q", tt.line, got, tt.want)
		}
	}
}
