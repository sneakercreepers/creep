package calibrate

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"
)

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
	ClassCodeInjection: codeMitigation,
	ClassDeserialization: func(code string) error {
		if strings.Contains(code, "deserialize_object(") {
			return errors.New("rebuilds typed objects")
		}
		return need(code, `= parse_json\(`, "parse plain data")
	},
}

const (
	refusalLine = `\n\s+return response\(4\d\d, none\)\n`
	literalList = `\[(?:"[a-z0-9.]+", )*"[a-z0-9.]+"\]`
)

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
	tests := []struct{ id, old, new string }{
		{"sqli-concat", `title = ?"`, `title = '" + term + "'"`},
		{"sqli-order", `if column not in ["title", "created"]:`, `if column == "":`},
		{"sqli-order", `    sql = "SELECT`, "    column = request.query(\"c\")\n    sql = \"SELECT"},
		{"nosql-find-one", `to_string(request.json("@@field@@"))`, `request.json("@@field@@")`},
		{"nosql-filter", `to_string(request.query("@@field@@"))`, `request.query("@@field@@")`},
		{"command-lookup", `if domain not in ["docs.example.invalid", "status.example.invalid"]:`, `if domain == "":`},
		{"command-lookup", `"docs.example.invalid"`, `"-oProxy"`},
		{"command-git", `^[a-z0-9][a-z0-9-]{0,39}$`, `^[a-z0-9-]{1,40}$`},
		{"command-git", `^[a-z0-9][a-z0-9-]{0,39}$`, `^[a-z0-9][a-z0-9-]{0,39}`},
		{"command-git", `run_process(["git"`, `shell(["git"`},
		{"path-read", `starts_with(path, "/srv/@@dir@@/")`, `starts_with(path, "/srv/@@dir@@")`},
		{"path-read", `real_path(join("/srv/@@dir@@", name))`, `join("/srv/@@dir@@", name)`},
		{"path-read", `    data = read_file(path)`, "    path = request.query(\"p\")\n    data = read_file(path)"},
		{"path-write", `^[a-z0-9_]{1,32}$`, `^[a-z0-9_.]{1,32}$`},
		{"path-write", `^[a-z0-9_]{1,32}$`, `^.{1,32}$`},
		{"ssrf-url", `url_of("https", "images.example.invalid", address.path)`, `url_of(address.scheme, address.host, address.path)`},
		{"ssrf-webhook", `if requested not in ["hooks.example.invalid", "alerts.example.invalid"]:`, `if requested == "":`},
		{"template-concat", `templates.render("Dear {{ who }}, your order has shipped.", {"who": name})`, `templates.render("Dear " + name, {})`},
		{"template-note", `templates.render("{{ user }}: {{ note }}", {"user": user.name, "note": note})`, `templates.render(note, {"user": user.name})`},
		{"code-eval", `to_number(expression)`, `eval(expression)`},
		{"code-compile", `{"double": 2, "triple": 3}`, `{"double": make_function("x", formula)}`},
		{"code-compile", "    if factor == none:\n        return response(400, none)\n", ""},
		{"deserialize-cookie", `parse_json(raw)`, `deserialize_object(raw)`},
		{"deserialize-job", `parse_json(request.body())`, `deserialize_object(request.body())`},
	}
	for _, tt := range tests {
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

func joinLines(v variant) string { return strings.Join(v.lines, "\n") + "\n" }

func need(code, pattern, what string) error {
	if !regexp.MustCompile(pattern).MatchString(code) {
		return fmt.Errorf("does not %s (want %s)", what, pattern)
	}
	return nil
}

// allowlisted reports whether name is refused unless it is one of fixed
// literals, and is not assigned again after the refusal.
func allowlisted(code, name string) bool {
	re := regexp.MustCompile(`if ` + name + ` not in ` + literalList + `:` + refusalLine)
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

func refusesAll(pattern *regexp.Regexp, attacks []string) error {
	for _, a := range attacks {
		if pattern.MatchString(a) {
			return fmt.Errorf("pattern %s accepts %q", pattern, a)
		}
	}
	return nil
}

// sqlMitigation: the query binds the value to a ? mark, or the value
// concatenated into it is one of fixed literals.
func sqlMitigation(code string) error {
	if need(code, `sql = "[^"+]*\?[^"+]*"\n\s+\w+ = db\.query\(sql, \[\w+\]\)`, "") == nil {
		return nil
	}
	m := regexp.MustCompile(`" \+ (\w+)\n`).FindStringSubmatch(code)
	if m != nil && allowlisted(code, m[1]) {
		return nil
	}
	return errors.New("neither binds the value nor concatenates only an allowlisted literal")
}

// nosqlMitigation: every caller value placed in a filter is made a string,
// so it cannot be an object of operators.
func nosqlMitigation(code string) error {
	inputs := strings.Count(code, "request.")
	if inputs == 0 || strings.Count(code, "to_string(request.") != inputs {
		return errors.New("a caller value reaches the filter without to_string")
	}
	return nil
}

// commandAttacks are arguments that start an option or reach a shell.
var commandAttacks = []string{"-p", "--all", "-oProxyCommand=id", "--output=/tmp/x", "a;id", "a b", "$(id)", "`id`", "a|id", "a&&id", ""}

// commandMitigation: a fixed program runs without a shell, and its one
// caller argument is an allowlisted literal or matches a pattern that
// refuses options and shell syntax.
func commandMitigation(code string) error {
	if strings.Contains(code, "shell(") {
		return errors.New("runs a shell")
	}
	m := regexp.MustCompile(`run_process\(\[(?:"[^"]+", )+(\w+)\]\)`).FindStringSubmatch(code)
	if m == nil {
		return errors.New("does not run a fixed program with one caller argument")
	}
	if allowlisted(code, m[1]) {
		return nil
	}
	pattern, ok := patternGuard(code, m[1])
	if !ok {
		return fmt.Errorf("%s is neither allowlisted nor checked against a pattern", m[1])
	}
	return refusesAll(pattern, commandAttacks)
}

// pathAttacks are names that leave, or name, the directory.
var pathAttacks = []string{"..", "../etc/passwd", "a/../../b", `..\b`, ".", ""}

// pathMitigation: the canonical path is checked to lie under its root,
// trailing slash included, or the caller's name matches a pattern that
// refuses every way out of the directory.
func pathMitigation(code string) error {
	contained := regexp.MustCompile(`(\w+) = real_path\(join\("([^"]+)", \w+\)\)\n\s+if not starts_with\((\w+), "([^"]+)"\):` + refusalLine)
	if m := contained.FindStringSubmatchIndex(code); m != nil {
		path, root, checked, prefix := code[m[2]:m[3]], code[m[4]:m[5]], code[m[6]:m[7]], code[m[8]:m[9]]
		if path == checked && prefix == root+"/" && !reassigned(code[m[1]:], path) {
			return nil
		}
	}
	m := regexp.MustCompile(`= "[^"]+/" \+ (\w+)\n`).FindStringSubmatch(code)
	if m == nil {
		return errors.New("neither confines the canonical path to its root nor checks the name")
	}
	pattern, ok := patternGuard(code, m[1])
	if !ok {
		return fmt.Errorf("%s reaches the path unchecked", m[1])
	}
	return refusesAll(pattern, pathAttacks)
}

// ssrfMitigation: the request goes to a URL built over https with a fixed
// host or an allowlisted one.
func ssrfMitigation(code string) error {
	m := regexp.MustCompile(`(?:(\w+) = )?url_of\("https", (?:"[a-z0-9.]+"|(\w+)), `).FindStringSubmatch(code)
	if m == nil {
		return errors.New("the request URL has no fixed scheme and host")
	}
	if m[2] != "" && !allowlisted(code, m[2]) {
		return fmt.Errorf("host %s is not allowlisted", m[2])
	}
	sink := `http_(?:get|post)\(url_of\(`
	if m[1] != "" {
		sink = `http_(?:get|post)\(` + m[1] + `[,)]`
	}
	return need(code, sink, "send the request to the built URL")
}

// codeMitigation: no caller text runs as code; the value is converted to a
// number or picks a value from a fixed map, refused when absent.
func codeMitigation(code string) error {
	if strings.Contains(code, "eval(") || strings.Contains(code, "make_function(") {
		return errors.New("runs text as code")
	}
	if strings.Contains(code, "to_number(") {
		return nil
	}
	fixedLookup := regexp.MustCompile(`(\w+) = \{(?:"\w+": \d+, )*"\w+": \d+\}\n\s+(\w+) = get\((\w+), \w+\)\n\s+if (\w+) == none:` + refusalLine)
	m := fixedLookup.FindStringSubmatch(code)
	if m == nil || m[1] != m[3] || m[2] != m[4] {
		return errors.New("neither converts the value nor looks it up in a fixed map")
	}
	return nil
}
