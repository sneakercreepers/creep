package verify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sneakercreepers/creep/internal/sandbox"
)

const testImage = "sha256:" + "ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12"

// fakeSecret stands in for what redact.File finds; the real redactor is
// tested end to end in internal/cli (TestBundleHoldsNoSecret).
const fakeSecret = "s3cr3t-value-from-the-app"

// maskSecret scrubs fakeSecret and fails on text holding "UNSCRUBBABLE",
// as redact.File fails on a line too long.
func maskSecret(text []byte) (string, error) {
	if bytes.Contains(text, []byte("UNSCRUBBABLE")) {
		return "", errors.New("line too long")
	}
	return strings.ReplaceAll(string(text), fakeSecret, "<SECRET_VALUE_1>"), nil
}

func testMeta() Meta {
	return Meta{
		Finding: "sink-3", Class: "template_injection", Commit: strings.Repeat("a", 40),
		Images: Images{App: testImage, Runner: sandbox.RunnerImage},
		Seed:   Seed{Migrations: []string{}, SHA256: SeedDigest([]string{"python", "migrate.py"})},
		Target: Target{Port: testPort},
	}
}

func repeated(t *testing.T, a app, req Request) (PoC, Repetition) {
	t.Helper()
	p := mustBuild(t, req)
	rep, err := Repeat(context.Background(), newFake(a), Target{Port: testPort}, p, DefaultRuns)
	if err != nil {
		t.Fatal(err)
	}
	return p, rep
}

// Protection (#25): every text in a bundle went through the scrub. The
// app's answers and the PoC's own header carry a secret, and none of it
// is in the bundle; a text the scrub cannot handle is withheld, and a PoC
// it cannot handle makes no bundle at all.
func TestBundleIsScrubbed(t *testing.T) {
	req := loadRequest(t, "http_request_header")
	req.HTTPRequest.Request.Headers = append(req.HTTPRequest.Request.Headers, Header{Name: "X-Api-Key", Value: fakeSecret})
	p, rep := repeated(t, func(r string, tables map[string]bool) (string, time.Duration) {
		body, d := welcomeApp(func(s string) string { return s })(r, tables)
		return body + "<!-- key " + fakeSecret + " -->", d
	}, req)
	b, err := NewBundle(testMeta(), p, rep, maskSecret)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := WriteBundle(&out, b); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), fakeSecret) {
		t.Fatalf("bundle holds the secret:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "<SECRET_VALUE_1>") || b.Rate != (Rate{5, 5}) || b.Runs[0].Steps[0].Withheld {
		t.Errorf("bundle not scrubbed as expected: rate %v\n%s", b.Rate, out.String())
	}

	_, rep = repeated(t, always(page("UNSCRUBBABLE")), loadRequest(t, "http_request_reflect"))
	b, err = NewBundle(testMeta(), mustBuild(t, loadRequest(t, "http_request_reflect")), rep, maskSecret)
	if err != nil {
		t.Fatal(err)
	}
	for _, run := range b.Runs {
		for _, s := range run.Steps {
			if !s.Withheld || s.Request != "" || s.Response != "" {
				t.Errorf("unscrubbable step kept: %+v", s)
			}
		}
	}

	failPoC := func(text []byte) (string, error) {
		if bytes.Contains(text, []byte(`"template"`)) {
			return "", errors.New("redactor full")
		}
		return string(text), nil
	}
	breakPoC := func(text []byte) (string, error) {
		return strings.Replace(string(text), `"template"`, `"<SECRET_VALUE_1>"`, 1), nil
	}
	// v0.2 release pentest: a marker in the path leaves a PoC reproduce
	// would refuse, so no bundle is written.
	invalidPoC := func(text []byte) (string, error) {
		return strings.Replace(string(text), `"path":"/`, `"path":"/<SECRET_VALUE_1>`, 1), nil
	}
	for name, scrub := range map[string]Scrub{"scrub fails": failPoC, "scrub breaks it": breakPoC, "scrub leaves it invalid": invalidPoC} {
		if _, err := NewBundle(testMeta(), p, rep, scrub); !errors.Is(err, ErrBundle) {
			t.Errorf("%s: %v, want ErrBundle", name, err)
		}
	}
	if _, err := NewBundle(testMeta(), PoC{}, rep, maskSecret); !errors.Is(err, ErrBundle) {
		t.Errorf("unbuilt PoC: %v", err)
	}
}

// TestReadBundle: a written bundle reads back whole; anything a run could
// not have written is refused.
func TestReadBundle(t *testing.T) {
	p, rep := repeated(t, scripted([]bool{true, false, true, true, false}), loadRequest(t, "http_request_reflect"))
	b, err := NewBundle(testMeta(), p, rep, maskSecret)
	if err != nil {
		t.Fatal(err)
	}
	var good bytes.Buffer
	if err := WriteBundle(&good, b); err != nil {
		t.Fatal(err)
	}
	back, err := ReadBundle(bytes.NewReader(good.Bytes()))
	if err != nil || back.Rate != (Rate{3, 5}) || back.Finding != "sink-3" {
		t.Fatalf("read back: %+v, %v", back.Rate, err)
	}
	if _, err := Build(back.PoC); err != nil {
		t.Errorf("bundle PoC does not build: %v", err)
	}
	edit := func(f func(m map[string]any)) []byte {
		var m map[string]any
		if err := json.Unmarshal(good.Bytes(), &m); err != nil {
			t.Fatal(err)
		}
		f(m)
		data, _ := json.Marshal(m)
		return data
	}
	bad := map[string][]byte{
		"unknown field": edit(func(m map[string]any) { m["extra"] = 1 }),
		"trailing data": append(bytes.Clone(good.Bytes()), []byte("{}")...),
		"version":       edit(func(m map[string]any) { m["version"] = 2 }),
		"finding":       edit(func(m map[string]any) { m["finding"] = "../x" }),
		"rate too high": edit(func(m map[string]any) { m["rate"] = map[string]int{"verified": 5, "runs": 5} }),
		"zero runs":     edit(func(m map[string]any) { m["rate"] = map[string]int{"verified": 0, "runs": 0}; m["runs"] = []any{} }),
		"commit":        edit(func(m map[string]any) { m["commit"] = "HEAD" }),
		"app image": edit(func(m map[string]any) {
			m["images"] = map[string]string{"app": "busybox", "runner": "", "database": ""}
		}),
		"outcome":        edit(func(m map[string]any) { m["runs"].([]any)[1].(map[string]any)["outcome"] = "verified!" }),
		"not an object":  []byte(`[]`),
		"over the limit": bytes.Repeat([]byte(" "), MaxBundleBytes+1),
	}
	for name, data := range bad {
		if _, err := ReadBundle(bytes.NewReader(data)); !errors.Is(err, ErrBundle) {
			t.Errorf("%s: %v, want ErrBundle", name, err)
		}
	}
}

// TestSeedDigest changes with any argument, split or order of the app's
// migrate step.
func TestSeedDigest(t *testing.T) {
	seen := map[string]string{}
	for name, cmd := range map[string][]string{
		"none": nil, "one": {"migrate"}, "two": {"python", "migrate.py"}, "swapped": {"migrate.py", "python"},
		"joined": {"pythonmigrate.py"}, "split": {"python", "migrate", ".py"}, "empty arg": {"python", "migrate.py", ""},
		"length in arg": {"1\x00a"}, "length split": {"1", "a"},
	} {
		d := SeedDigest(cmd)
		if other, dup := seen[d]; dup || len(d) != 64 {
			t.Errorf("%s: digest %s, same as %s", name, d, other)
		}
		seen[d] = name
	}
}
