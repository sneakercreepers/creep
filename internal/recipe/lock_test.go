package recipe

import (
	"errors"
	"strings"
	"testing"
)

// lockJSON is a one-entry lock with fields replaced by the overrides.
func lockJSON(source, commit, file, checksum string) string {
	return `{"version": 1, "recipes": [{"source": "` + source + `", "commit": "` + commit + `", "file": "` + file + `", "checksum": "` + checksum + `"}]}`
}

// TestLockRoundTrip: what Install writes, ParseLock reads back; a second
// install of a source replaces its entries and keeps the others.
func TestLockRoundTrip(t *testing.T) {
	a, _ := ParseSource("github.com/acme/recipes@" + testCommit)
	b, _ := ParseSource("github.com/other/r@" + strings.Repeat("a", 40))
	l := NewLock().Install(a, map[string][]byte{"sqli.json": []byte("one"), "cmd.json": []byte("two")})
	l = l.Install(b, map[string][]byte{"x.json": []byte("three")})
	a2 := a
	a2.Commit = strings.Repeat("b", 40)
	l = l.Install(a2, map[string][]byte{"sqli.json": []byte("new")})
	data, err := l.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseLock(data)
	if err != nil {
		t.Fatalf("ParseLock(Marshal) = %v\n%s", err, data)
	}
	if len(got.Recipes) != 2 || got.Recipes[0].Commit != a2.Commit || got.Recipes[0].File != "sqli.json" || got.Recipes[1].Source != "github.com/other/r" {
		t.Fatalf("lock after reinstall = %+v", got.Recipes)
	}
	if got.Recipes[0].Path() != "acme/recipes/"+a2.Commit+"/sqli.json" {
		t.Errorf("Path = %q", got.Recipes[0].Path())
	}
	if err := got.Recipes[0].Verify([]byte("new")); err != nil {
		t.Errorf("Verify of the installed bytes: %v", err)
	}
	if empty, err := ParseLock([]byte(`{"version": 1, "recipes": []}`)); err != nil || len(empty.Recipes) != 0 {
		t.Errorf("empty lock: %+v, %v", empty, err)
	}
}

// TestVerifyRefusesTampering: any change to an installed file, even one
// byte, an appended newline or an empty file, fails its checksum.
func TestVerifyRefusesTampering(t *testing.T) {
	orig := []byte(`{"version": 1}`)
	p := Pin{Source: "github.com/acme/recipes", Commit: testCommit, File: "a.json", Checksum: Checksum(orig)}
	if err := p.Verify(orig); err != nil {
		t.Fatalf("Verify(original) = %v", err)
	}
	for _, changed := range []string{`{"version": 2}`, string(orig) + "\n", "", " " + string(orig)} {
		if err := p.Verify([]byte(changed)); !errors.Is(err, ErrTampered) {
			t.Errorf("Verify(%q) = %v; want ErrTampered", changed, err)
		}
	}
}

// TestParseLockRefuses: the lock is as strict as a recipe, and every entry
// names one safe path segment per part, so a tampered lock cannot point a
// scan outside the store or at a branch.
func TestParseLockRefuses(t *testing.T) {
	sum := Checksum([]byte("x"))
	src := "github.com/acme/recipes"
	tests := map[string]string{
		"not JSON":            "{",
		"trailing data":       lockJSON(src, testCommit, "a.json", sum) + "{}",
		"unknown field":       `{"version": 1, "recipes": [], "extra": 1}`,
		"repeated key":        `{"version": 1, "version": 1, "recipes": []}`,
		"case-variant key":    `{"Version": 1, "recipes": []}`,
		"version 2":           `{"version": 2, "recipes": []}`,
		"upper-case source":   lockJSON("github.com/Acme/recipes", testCommit, "a.json", sum),
		"other host":          lockJSON("gitlab.com/acme/recipes", testCommit, "a.json", sum),
		"branch commit":       lockJSON(src, "main", "a.json", sum),
		"short commit":        lockJSON(src, testCommit[:12], "a.json", sum),
		"traversal file":      lockJSON(src, testCommit, "../a.json", sum),
		"separator in file":   lockJSON(src, testCommit, "x/a.json", sum),
		"backslash in file":   lockJSON(src, testCommit, `x\\a.json`, sum),
		"hidden file":         lockJSON(src, testCommit, ".a.json", sum),
		"not json file":       lockJSON(src, testCommit, "a.txt", sum),
		"device file":         lockJSON(src, testCommit, "con.json", sum),
		"device repository":   lockJSON("github.com/acme/nul", testCommit, "a.json", sum),
		"trailing-dot repo":   lockJSON("github.com/acme/r.", testCommit, "a.json", sum),
		"traversal repo":      lockJSON("github.com/acme/..", testCommit, "a.json", sum),
		"no checksum prefix":  lockJSON(src, testCommit, "a.json", strings.TrimPrefix(sum, "sha256:")),
		"short checksum":      lockJSON(src, testCommit, "a.json", sum[:20]),
		"upper-case checksum": lockJSON(src, testCommit, "a.json", strings.ToUpper(sum)),
		"two commits": `{"version": 1, "recipes": [` +
			`{"source": "` + src + `", "commit": "` + testCommit + `", "file": "a.json", "checksum": "` + sum + `"},` +
			`{"source": "` + src + `", "commit": "` + strings.Repeat("a", 40) + `", "file": "b.json", "checksum": "` + sum + `"}]}`,
		"file twice": `{"version": 1, "recipes": [` +
			`{"source": "` + src + `", "commit": "` + testCommit + `", "file": "a.json", "checksum": "` + sum + `"},` +
			`{"source": "` + src + `", "commit": "` + testCommit + `", "file": "a.json", "checksum": "` + sum + `"}]}`,
		"too large":  `{"version": 1, "recipes": []}` + strings.Repeat(" ", MaxLockBytes),
		"not UTF-8":  "{\"version\": 1, \"recipes\": [], \"\xff\": 1}",
		"null entry": `{"version": 1, "recipes": [null]}`,
	}
	for name, data := range tests {
		if _, err := ParseLock([]byte(data)); !errors.Is(err, ErrLock) {
			t.Errorf("%s: ParseLock = %v; want ErrLock", name, err)
		}
	}
	var many strings.Builder
	many.WriteString(`{"version": 1, "recipes": [`)
	for i := range MaxLockEntries + 1 {
		if i > 0 {
			many.WriteString(",")
		}
		many.WriteString(`{"source": "` + src + `", "commit": "` + testCommit + `", "file": "f` + strings.Repeat("a", i%50) + string(rune('a'+i%26)) + `.json", "checksum": "` + sum + `"}`)
	}
	many.WriteString("]}")
	if _, err := ParseLock([]byte(many.String())); !errors.Is(err, ErrLock) {
		t.Errorf("a lock over %d entries: %v", MaxLockEntries, err)
	}
}

// TestValidFileName holds installed names to one portable path segment.
func TestValidFileName(t *testing.T) {
	for name, want := range map[string]bool{
		"sqli.json": true, "a.json": true, "a_b-1.json": true, strings.Repeat("a", 59) + ".json": true,
		strings.Repeat("a", 60) + ".json": false, ".json": false, "-a.json": false, "A.json": false,
		"a.JSON": false, "a.json.txt": false, "a b.json": false, "a/b.json": false, "a..json": false,
	} {
		if got := ValidFileName(name); got != want {
			t.Errorf("ValidFileName(%q) = %v, want %v", name, got, want)
		}
	}
}
