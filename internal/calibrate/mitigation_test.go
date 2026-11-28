package calibrate

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
)

// classSinks are the dangerous builtins of each class. Both twins of a
// template call the same one, so a model cannot score by spotting a name:
// the twins differ only by the defense (#377 audit).
var classSinks = map[Class]*regexp.Regexp{
	ClassSQLi:              regexp.MustCompile(`db\.query\(`),
	ClassNoSQLInjection:    regexp.MustCompile(`store\.(?:find|first)\(`),
	ClassCommandInjection:  regexp.MustCompile(`shell\(`),
	ClassPathTraversal:     regexp.MustCompile(`(?:read|write)_file\(`),
	ClassSSRF:              regexp.MustCompile(`http_(?:get|post)\(`),
	ClassTemplateInjection: regexp.MustCompile(`templates\.render\(`),
	ClassCodeInjection:     regexp.MustCompile(`eval\(|make_function\(`),
	ClassDeserialization:   regexp.MustCompile(`deserialize_object\(`),
}

// mitigations hold, per class, the specific defense a safe twin must use
// (#358 review). A guard that merely looks like one (a refusal on the wrong
// condition, a pattern that lets a separator through, a prefix without its
// trailing slash) fails, so a weakened twin cannot stay in the set.
var mitigations = map[Class]func(code string) error{
	ClassSQLi:             sqlMitigation,
	ClassNoSQLInjection:   nosqlMitigation,
	ClassCommandInjection: commandMitigation,
	ClassPathTraversal:    pathMitigation,
	ClassSSRF:             ssrfMitigation,
	ClassTemplateInjection: func(code string) error {
		return need(code, `templates\.render\("[^"]*", \{[^}]*\}\)`, "render a literal template")
	},
	ClassCodeInjection:   codeMitigation,
	ClassDeserialization: deserializationMitigation,
}

const (
	refusalLine = `\n\s+return response\(4\d\d, none\)\n`
	hostLiteral = `"[a-z0-9.]+"`
	codeLiteral = `"[a-z0-9 *+-]+"`
)

func TestBothTwinsCallTheClassSink(t *testing.T) {
	cat, err := defaultCatalog()
	if err != nil {
		t.Fatal(err)
	}
	for _, tpl := range cat.templates {
		sink, ok := classSinks[tpl.class]
		if !ok {
			t.Fatalf("class %s has no sink", tpl.class)
		}
		for name, v := range map[string]variant{"vulnerable": tpl.vuln, "safe": tpl.safe} {
			if line := v.lines[v.sinkLine-1]; !sink.MatchString(line) {
				t.Errorf("%s %s sink line %q does not call %s", tpl.id, name, line, sink)
			}
		}
	}
}

// The vulnerable twin of every template fails its class's check, and the
// safe twin passes: the check names the fix, not the shape of the code.
func TestSafeTwinsUseTheirClassMitigation(t *testing.T) {
	cat, err := defaultCatalog()
	if err != nil {
		t.Fatal(err)
	}
	for _, tpl := range cat.templates {
		check, ok := mitigations[tpl.class]
		if !ok {
			t.Fatalf("class %s has no mitigation check", tpl.class)
		}
		if err := check(joinLines(tpl.safe)); err != nil {
			t.Errorf("%s safe twin: %v", tpl.id, err)
		}
		if check(joinLines(tpl.vuln)) == nil {
			t.Errorf("%s vulnerable twin passes its class's mitigation check", tpl.id)
		}
	}
}

// Each weakening keeps the twin's shape but breaks its defense; the
// mitigation check refuses every one.
func TestMitigationChecksRefuseWeakenedGuards(t *testing.T) {
	cat, err := defaultCatalog()
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range weakenings() {
		tpl := templateByID(t, cat, tt.id)
		code := joinLines(tpl.safe)
		if !strings.Contains(code, tt.old) {
			t.Fatalf("%s safe twin lacks %q", tt.id, tt.old)
		}
		weak := strings.Replace(code, tt.old, tt.new, 1)
		if mitigations[tpl.class](weak) == nil {
			t.Errorf("%s weakened by %q passes:\n%s", tt.id, tt.new, weak)
		}
	}
}

func weakenings() []struct{ id, old, new string } {
	return []struct{ id, old, new string }{
		{"sqli-concat", `title = ?"`, `title = '" + term + "'"`},
		{"sqli-order", `if column not in ["title", "created"]:`, `if column == "":`},
		{"sqli-order", `    sql = "SELECT`, "    column = request.query(\"c\")\n    sql = \"SELECT"},
		{"nosql-find-one", `to_string(request.json("@@field@@"))`, `request.json("@@field@@")`},
		{"nosql-filter", `to_string(request.query("@@field@@"))`, `request.query("@@field@@")`},
		{"command-lookup", `if domain not in ["docs.example.invalid", "status.example.invalid"]:`, `if domain == "":`},
		{"command-lookup", `"docs.example.invalid"`, `"-oProxy"`},
		{"command-lookup", `    output = shell(`, "    domain = request.query(\"d\")\n    output = shell("},
		{"command-git", `^[a-z0-9][a-z0-9-]{0,39}$`, `^[a-z0-9-]{1,40}$`},
		{"command-git", `^[a-z0-9][a-z0-9-]{0,39}$`, `^[a-z0-9][a-z0-9-]{0,39}`},
		{"command-git", `^[a-z0-9][a-z0-9-]{0,39}$`, `^[a-z0-9][a-z0-9 ;-]{0,39}$`},
		{"path-read", `starts_with(path, "/srv/@@dir@@/")`, `starts_with(path, "/srv/@@dir@@")`},
		{"path-read", `real_path(join("/srv/@@dir@@", name))`, `join("/srv/@@dir@@", name)`},
		{"path-read", `    data = read_file(path)`, "    path = request.query(\"p\")\n    data = read_file(path)"},
		{"path-write", `^[a-z0-9_]{1,32}$`, `^[a-z0-9_.]{1,32}$`},
		{"path-write", `^[a-z0-9_]{1,32}$`, `^.{1,32}$`},
		{"ssrf-url", `url_of("https", "images.example.invalid", address.path)`, `url_of(address.scheme, address.host, address.path)`},
		{"ssrf-webhook", `if requested not in ["hooks.example.invalid", "alerts.example.invalid"]:`, `if requested == "":`},
		{"template-concat", `templates.render("Dear {{ who }}, your order has shipped.", {"who": name})`, `templates.render("Dear " + name, {})`},
		{"template-note", `templates.render("{{ user }}: {{ note }}", {"user": user.name, "note": note})`, `templates.render(note, {"user": user.name})`},
		{"code-eval", `{0,8}$"`, `{0,8}"`},
		{"code-eval", `( [+*-] [0-9]{1,9})`, `( [+*-] [0-9a-z_(); ]{1,9})`},
		{"code-compile", "    if formula not in [\"x * 2\", \"x * 3\"]:\n        return response(400, none)\n", ""},
		{"code-compile", `"x * 3"]`, `"x * 3", "x; system(x)"]`},
		{"deserialize-cookie", `deserialize_object(raw, ["map", "text"])`, `deserialize_object(raw)`},
		{"deserialize-cookie", `["map", "text"]`, `["map", "text", "process"]`},
		{"deserialize-job", `deserialize_object(request.body(), ["map", "text"])`, `deserialize_object(request.body())`},
	}
}

func joinLines(v variant) string { return strings.Join(v.lines, "\n") + "\n" }

func need(code, pattern, what string) error {
	if !regexp.MustCompile(pattern).MatchString(code) {
		return fmt.Errorf("does not %s (want %s)", what, pattern)
	}
	return nil
}

// allowlisted reports whether name is refused unless it is one of fixed
// literals of the given shape, and is not assigned again after the refusal.
func allowlisted(code, name, literal string) bool {
	list := `\[(?:` + literal + `, )*` + literal + `\]`
	re := regexp.MustCompile(`if ` + name + ` not in ` + list + `:` + refusalLine)
	loc := re.FindStringIndex(code)
	return loc != nil && !reassigned(code[loc[1]:], name)
}

func reassigned(code, name string) bool {
	return regexp.MustCompile(`(?m)^\s*` + name + ` = `).MatchString(code)
}

// patternGuard returns the regex name must match before the code goes on,
// when it is not assigned again after the check.
func patternGuard(code, name string) (*regexp.Regexp, bool) {
	re := regexp.MustCompile(`if not matches\(` + name + `, "([^"]+)"\):` + refusalLine)
	m := re.FindStringSubmatchIndex(code)
	if m == nil || reassigned(code[m[1]:], name) {
		return nil, false
	}
	pattern, err := regexp.Compile(code[m[2]:m[3]])
	return pattern, err == nil
}

// guardedBy checks that name is an allowlisted literal of the given shape
// (none when literal is empty) or matches a pattern that refuses every
// attack.
func guardedBy(code, name, literal string, attacks []string) error {
	if literal != "" && allowlisted(code, name, literal) {
		return nil
	}
	pattern, ok := patternGuard(code, name)
	if !ok {
		return fmt.Errorf("%s is neither allowlisted nor checked against a pattern", name)
	}
	for _, a := range attacks {
		if pattern.MatchString(a) {
			return fmt.Errorf("pattern %s accepts %q", pattern, a)
		}
	}
	return nil
}
