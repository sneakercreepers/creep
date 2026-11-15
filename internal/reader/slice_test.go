package reader

import (
	"errors"
	"fmt"
	"io/fs"
	"reflect"
	"strings"
	"testing"

	"github.com/sneakercreepers/creep/internal/gateway"
	"github.com/sneakercreepers/creep/internal/redact"
)

// app is a Flask handler whose query reaches a SQL sink through two
// assignments, with a guard and an unrelated line in between.
const app = `from flask import Flask, request
app = Flask(__name__)

@app.route("/users")
@login_required
def users():
    name = request.args["name"]
    unused = 42
    if not name:
        return "missing", 400
    query = "SELECT * FROM users WHERE name = '" + name + "'"
    cursor = db.cursor()
    cursor.execute(query)
    return "ok"
`

// sqlTarget points at app's handler and sink.
func sqlTarget(h HypothesisID, path string) Target {
	return Target{Hypothesis: h, Class: ClassSQLInjection, Path: path, SourceLine: 6, SinkLine: 13}
}

func newRedactor(t *testing.T) *redact.Redactor {
	t.Helper()
	r, err := redact.New()
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// files is a fake repository; Read records every path it is asked for.
type files struct {
	content map[string]string
	read    []string
}

func (f *files) slicer(t *testing.T, tier Tier) Slicer {
	t.Helper()
	return Slicer{Redactor: newRedactor(t), Tier: tier, Read: func(path string) ([]byte, error) {
		f.read = append(f.read, path)
		c, ok := f.content[path]
		if !ok {
			return nil, fmt.Errorf("open %s: %w", path, fs.ErrNotExist)
		}
		return []byte(c), nil
	}}
}

func build(t *testing.T, tier Tier, content map[string]string, targets ...Target) SliceReport {
	t.Helper()
	rep, err := (&files{content: content}).slicer(t, tier).Build(targets)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return rep
}

func TestBuildPicksTheFlow(t *testing.T) {
	rep := build(t, TierM, map[string]string{"app.py": app}, sqlTarget(7, "app.py"))
	if len(rep.Slices) != 1 || rep.NotEvaluated != nil || rep.NotScanned != nil {
		t.Fatalf("report = %+v; want one slice", rep)
	}
	s := rep.Slices[0]
	want := "HYPOTHESIS: sql_injection, source line 6, sink line 13\nCODE:\n" +
		"4| @app.route(\"/users\")\n5| @login_required\n6| def users():\n" +
		"7|     name = request.args[\"name\"]\n" +
		"9|     if not name:\n10|         return \"missing\", 400\n" +
		"11|     query = \"SELECT * FROM users WHERE name = '\" + name + \"'\"\n" +
		"12|     cursor = db.cursor()\n13|     cursor.execute(query)\n"
	if s.Text != want || s.Partial || s.Hypothesis != 7 {
		t.Fatalf("slice = %+v\ntext:\n%s\nwant:\n%s", s, s.Text, want)
	}
	if shown := []LineRange{{4, 7}, {9, 13}}; !reflect.DeepEqual(s.Shown, shown) {
		t.Fatalf("Shown = %v, want %v", s.Shown, shown)
	}
}

// Project accepts citations of shown lines only, so the unrelated line 8
// and lines outside the handler are refused.
func TestSliceShownBoundsEvidence(t *testing.T) {
	s := build(t, TierS, map[string]string{"app.py": app}, sqlTarget(1, "app.py")).Slices[0]
	conf := 90
	for _, tt := range []struct {
		start, end int
		ok         bool
	}{{11, 13, true}, {6, 7, true}, {8, 8, false}, {7, 9, false}, {14, 14, false}, {1, 1, false}} {
		a := Answer{Verdict: answerVulnerable, Evidence: []Evidence{{tt.start, tt.end}}, Confidence: &conf}
		_, err := Project(1, a, s.Shown)
		if (err == nil) != tt.ok {
			t.Errorf("evidence %d-%d: err = %v, want ok %v", tt.start, tt.end, err, tt.ok)
		}
	}
}

// Acceptance (#94): code is fragmented only after redact.File has redacted
// the whole file. The AWS secret on the sink line is masked only because
// the key id far above it, outside the slice, is in the same File call.
func TestBuildMasksSecretsInSlices(t *testing.T) {
	keyID := "AKIA" + "QYLPMN5HHHFPZAM2"
	awsBare := "wJalrXUtnFEMI" + "/K7MDENG/bPx" + "RfiCY" + "EXAMPLEKEY"
	email := "alice.smith" + "@example.com"
	password := "hunter2" + "-Tr0ub4dor"
	src := "AWS_KEY_ID = \"" + keyID + "\"\n" + strings.Repeat("\n", 40) +
		"@app.route(\"/run\")\ndef run():\n" +
		"    password = \"" + password + "\"\n" +
		"    to = request.args[\"to\"] or \"" + email + "\"\n" +
		"    cmd = \"mail \" + to + \" " + awsBare + " \" + password\n" +
		"    os.system(cmd)\n"
	sink := 42 + 5
	target := Target{Hypothesis: 3, Class: ClassCommandInjection, Path: "run.py", SourceLine: 43, SinkLine: sink}
	for _, tier := range tiers {
		s := build(t, tier, map[string]string{"run.py": src}, target).Slices[0]
		for _, raw := range []string{keyID, awsBare, email, password} {
			if strings.Contains(s.Text, raw) {
				t.Errorf("tier %s: slice leaks %q:\n%s", tier, raw, s.Text)
			}
		}
		if !strings.Contains(s.Text, "os.system(cmd)") || len(s.Redactions) == 0 {
			t.Errorf("tier %s: slice lacks the sink or redaction counts: %+v", tier, s)
		}
	}
}

// Acceptance (#94): a file redact.File rejects, or one that cannot be read
// (missing or renamed since static ran), is never sliced, raw or truncated;
// it is listed as not scanned and the run goes on.
func TestBuildSkipsFilesRedactRejects(t *testing.T) {
	tests := []struct {
		name    string
		content string
		missing bool
		want    gateway.SkipReason
	}{
		{"too large", "CANARY\n" + strings.Repeat("x = 1\n", redact.MaxFileBytes/6), false, gateway.SkipTooLarge},
		{"minified", "CANARY;" + strings.Repeat("a=1;", redact.MaxLineBytes/4), false, gateway.SkipLineTooLong},
		{"binary with NUL", "CANARY" + strings.Repeat("\x00\x01", redact.MaxLineBytes/2), false, gateway.SkipLineTooLong},
		{"CR-only line ends", strings.Repeat("CANARY x\r", redact.MaxLineBytes/9+1), false, gateway.SkipLineTooLong},
		{"missing or renamed", "", true, gateway.SkipReadFailed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			content := map[string]string{"a.py": app, "c.py": app}
			if !tt.missing {
				content["b.py"] = tt.content
			}
			rep := build(t, TierS, content, sqlTarget(1, "a.py"), sqlTarget(2, "b.py"), sqlTarget(3, "c.py"), sqlTarget(4, "b.py"))
			if rep.Incomplete || len(rep.Slices) != 2 || rep.Slices[0].Hypothesis != 1 || rep.Slices[1].Hypothesis != 3 {
				t.Fatalf("report = %+v; want slices for 1 and 3 only", rep)
			}
			wantFiles := []gateway.NotScanned{{Path: "b.py", Reason: tt.want}}
			wantSkips := []NotEvaluated{{2, SkipFileNotScanned}, {4, SkipFileNotScanned}}
			if !reflect.DeepEqual(rep.NotScanned, wantFiles) || !reflect.DeepEqual(rep.NotEvaluated, wantSkips) {
				t.Fatalf("NotScanned %v, NotEvaluated %v; want %v, %v", rep.NotScanned, rep.NotEvaluated, wantFiles, wantSkips)
			}
			for _, s := range rep.Slices {
				if strings.Contains(s.Text, "CANARY") {
					t.Fatalf("rejected file reached a slice: %q", s.Text)
				}
			}
		})
	}
}

// fillingFile holds more distinct values than one run can remember: values
// made of one repeated byte share every window, so they fill the sweep
// index's window and overflow lists after a few hundred.
func fillingFile() string {
	var b strings.Builder
	for n := range 300 {
		b.WriteString("CANARY password = \"" + strings.Repeat("@", 8+n) + "\"\n")
	}
	return b.String()
}

// Acceptance (#94): ErrRunFull stops the run. That file and every later one
// are listed as not scanned and never read, their hypotheses are not
// evaluated, and the report is incomplete, never clean.
func TestBuildStopsWhenRunFull(t *testing.T) {
	f := &files{content: map[string]string{"a.py": app, "b.py": fillingFile(), "c.py": app, "d.py": app}}
	targets := []Target{sqlTarget(1, "a.py"), sqlTarget(2, "b.py"), sqlTarget(3, "c.py"), sqlTarget(4, "d.py"), sqlTarget(5, "c.py")}
	rep, err := f.slicer(t, TierM).Build(targets)
	if !errors.Is(err, redact.ErrRunFull) || !rep.Incomplete {
		t.Fatalf("Build = %+v, %v; want ErrRunFull and an incomplete report", rep, err)
	}
	wantFiles := []gateway.NotScanned{{Path: "b.py", Reason: gateway.SkipRunFull}, {Path: "c.py", Reason: gateway.SkipRunFull}, {Path: "d.py", Reason: gateway.SkipRunFull}}
	wantSkips := []NotEvaluated{{2, SkipRunFull}, {3, SkipRunFull}, {5, SkipRunFull}, {4, SkipRunFull}}
	if !reflect.DeepEqual(rep.NotScanned, wantFiles) || !reflect.DeepEqual(rep.NotEvaluated, wantSkips) {
		t.Fatalf("NotScanned %v, NotEvaluated %v; want %v, %v", rep.NotScanned, rep.NotEvaluated, wantFiles, wantSkips)
	}
	if len(rep.Slices) != 1 || rep.Slices[0].Hypothesis != 1 || !reflect.DeepEqual(f.read, []string{"a.py", "b.py"}) {
		t.Fatalf("slices %+v after reading %v; want only a.py sliced and nothing read after b.py", rep.Slices, f.read)
	}
}

// Lines that do not exist in the redacted file are never shown: a stale
// target after an edit, a zero line, or redaction joining lines so later
// numbers no longer match the file.
func TestBuildRefusesLinesItCannotShow(t *testing.T) {
	body := strings.Repeat(strings.Repeat("Qx7", 21)+"\n", 3)
	key := "-----BEGIN RSA PRIV" + "ATE KEY-----\n" + body + "-----END RSA PRIV" + "ATE KEY-----\n"
	tests := []struct {
		name   string
		src    string
		target Target
		want   SkipReason
	}{
		{"sink past the end", app, Target{1, ClassSQLInjection, "f.py", 6, 99}, SkipLineRange},
		{"source past the end", app, Target{1, ClassSQLInjection, "f.py", 99, 13}, SkipLineRange},
		{"zero line", app, Target{1, ClassSQLInjection, "f.py", 0, 13}, SkipLineRange},
		{"negative line", app, Target{1, ClassSQLInjection, "f.py", 6, -1}, SkipLineRange},
		{"multi-line key joined", "KEY = \"\"\"\n" + key + "\"\"\"\n" + app, Target{1, ClassSQLInjection, "f.py", 12, 19}, SkipLinesShifted},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rep := build(t, TierL, map[string]string{"f.py": tt.src}, tt.target)
			want := []NotEvaluated{{1, tt.want}}
			if len(rep.Slices) != 0 || rep.Incomplete || !reflect.DeepEqual(rep.NotEvaluated, want) {
				t.Fatalf("report = %+v; want only %v", rep, want)
			}
			// A shifted file was redacted but never sliced, so it is listed
			// as not scanned too; a stale line leaves the file scanned.
			var wantFiles []gateway.NotScanned
			if tt.want == SkipLinesShifted {
				wantFiles = []gateway.NotScanned{{Path: "f.py", Reason: FileLinesShifted}}
			}
			if !reflect.DeepEqual(rep.NotScanned, wantFiles) {
				t.Fatalf("NotScanned = %v, want %v", rep.NotScanned, wantFiles)
			}
		})
	}
}

func TestBuildNeedsValidInput(t *testing.T) {
	read := func(string) ([]byte, error) { return []byte(app), nil }
	r := newRedactor(t)
	tests := []struct {
		name    string
		s       Slicer
		targets []Target
		want    error
	}{
		{"no redactor", Slicer{Tier: TierS, Read: read}, nil, ErrSlicer},
		{"no read", Slicer{Redactor: r, Tier: TierS}, nil, ErrSlicer},
		{"unknown tier", Slicer{Redactor: r, Tier: "XL", Read: read}, nil, ErrTier},
		{"no class", Slicer{Redactor: r, Tier: TierS, Read: read}, []Target{{Path: "a.py", SourceLine: 1, SinkLine: 1}}, ErrSlicer},
		{"unknown class", Slicer{Redactor: r, Tier: TierS, Read: read}, []Target{{Class: 99, Path: "a.py", SourceLine: 1, SinkLine: 1}}, ErrSlicer},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := tt.s.Build(tt.targets); !errors.Is(err, tt.want) {
				t.Fatalf("Build err = %v, want %v", err, tt.want)
			}
		})
	}
}
