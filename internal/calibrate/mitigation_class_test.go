package calibrate

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// sqlMitigation: the query binds the value to a ? mark, or the value
// concatenated into it is one of fixed literals.
func sqlMitigation(code string) error {
	if need(code, `sql = "[^"+]*\?[^"+]*"\n\s+\w+ = db\.query\(sql, \[\w+\]\)`, "") == nil {
		return nil
	}
	m := regexp.MustCompile(`" \+ (\w+)\n`).FindStringSubmatch(code)
	if m != nil && allowlisted(code, m[1], `"[a-z]+"`) {
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
var commandAttacks = []string{"-p", "--all", "-oProxyCommand=id", "a;id", "a b", "$(id)", "`id`", "a|id", "a&&id", "a\nid", ""}

// commandMitigation: the shell gets a fixed command and one caller value
// that is an allowlisted literal or matches a pattern refusing options and
// shell syntax.
func commandMitigation(code string) error {
	m := regexp.MustCompile(`shell\("[^"]*" \+ (\w+)\)`).FindStringSubmatch(code)
	if m == nil {
		return errors.New("does not run a fixed command with one caller value")
	}
	return guardedBy(code, m[1], hostLiteral, commandAttacks)
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
	return guardedBy(code, m[1], "", pathAttacks)
}

// ssrfMitigation: the request goes to a URL built over https with a fixed
// host or an allowlisted one.
func ssrfMitigation(code string) error {
	m := regexp.MustCompile(`(?:(\w+) = )?url_of\("https", (?:"[a-z0-9.]+"|(\w+)), `).FindStringSubmatch(code)
	if m == nil {
		return errors.New("the request URL has no fixed scheme and host")
	}
	if m[2] != "" && !allowlisted(code, m[2], hostLiteral) {
		return fmt.Errorf("host %s is not allowlisted", m[2])
	}
	sink := `http_(?:get|post)\(url_of\(`
	if m[1] != "" {
		sink = `http_(?:get|post)\(` + m[1] + `[,)]`
	}
	return need(code, sink, "send the request to the built URL")
}

// codeAttacks are inputs that do more than arithmetic once run as code.
var codeAttacks = []string{"1; system(1)", "f(1)", "a", "1 + a", `"x"`, "1 +", "x.y", "1\n2", ""}

// codeMitigation: the text run as code is an allowlisted literal or matches
// a pattern that admits only arithmetic on numbers.
func codeMitigation(code string) error {
	m := regexp.MustCompile(`(?:eval\(|make_function\("\w+", "return " \+ )(\w+)\)`).FindStringSubmatch(code)
	if m == nil {
		return errors.New("runs no single caller value as code")
	}
	return guardedBy(code, m[1], codeLiteral, codeAttacks)
}

// plainTypes are the types the task prompt names as plain data.
var plainTypes = []string{"map", "list", "text", "number"}

// deserializationMitigation: every deserialize_object call lists the types
// it may rebuild, and they are plain data only.
func deserializationMitigation(code string) error {
	calls := strings.Count(code, "deserialize_object(")
	lists := regexp.MustCompile(`deserialize_object\([^\n]+, \[((?:"[a-z]+", )*"[a-z]+")\]\)`).FindAllStringSubmatch(code, -1)
	if calls == 0 || len(lists) != calls {
		return errors.New("rebuilds objects of any type")
	}
	for _, l := range lists {
		for _, typ := range strings.Split(l[1], ", ") {
			if !slices.Contains(plainTypes, strings.Trim(typ, `"`)) {
				return fmt.Errorf("rebuilds type %s, which is not plain data", typ)
			}
		}
	}
	return nil
}
