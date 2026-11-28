package calibrate

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

var (
	stringLiteralRe = regexp.MustCompile(`"(?:[^"\\]|\\.)*"`)
	// codeTokenRe is a name, a dotted name or a field access, and whether a
	// call follows it.
	codeTokenRe = regexp.MustCompile(`(\.?[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)(\()?`)
	assignRe    = regexp.MustCompile(`^\s*(?:let\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=[^=]`)
	handlerRe   = regexp.MustCompile(`^handler\s+([A-Za-z_][A-Za-z0-9_]*)\(([A-Za-z_][A-Za-z0-9_]*)\)`)
)

// unknownNames returns every name in code that is not a keyword, a builtin
// the task prompt defines, a builtin field read from a local, or a local:
// the handler, its parameter and every assigned name. Any API of a real
// language is unknown, so it cannot slip into the task set (#358).
func unknownNames(code string) []string {
	calls, fields := builtins()
	locals := localNames(code)
	var unknown []string
	for _, line := range strings.Split(stringLiteralRe.ReplaceAllString(code, `""`), "\n") {
		if handlerRe.MatchString(line) {
			continue // declares the handler and its parameter, both locals
		}
		for _, m := range codeTokenRe.FindAllStringSubmatch(line, -1) {
			if !knownName(m[1], m[2] != "", calls, fields, locals) {
				unknown = append(unknown, m[0])
			}
		}
	}
	return unknown
}

// knownName: a call must be a builtin or a local (the function
// make_function returned), a dotted name a builtin field read from a local,
// and a bare name a keyword or a local.
func knownName(name string, called bool, calls, fields, locals map[string]bool) bool {
	if called {
		return calls[name] || locals[name]
	}
	if recv, field, dotted := strings.Cut(name, "."); dotted {
		return locals[recv] && fields[field]
	}
	return locals[name] || slices.Contains(strings.Fields(keywordList), name)
}

func localNames(code string) map[string]bool {
	locals := map[string]bool{}
	for _, line := range strings.Split(code, "\n") {
		if m := handlerRe.FindStringSubmatch(line); m != nil {
			locals[m[1]], locals[m[2]] = true, true
		}
		if m := assignRe.FindStringSubmatch(line); m != nil {
			locals[m[1]] = true
		}
	}
	return locals
}

// Acceptance (#358): every name in every generated task, fillers and slot
// values included, is one the task prompt defines or the task assigns.
func TestTaskSetUsesOnlyPromptBuiltins(t *testing.T) {
	for _, seed := range budgetSeeds {
		for _, task := range mustGenerate(t, seed) {
			if unknown := unknownNames(task.Code); len(unknown) > 0 {
				t.Errorf("seed %d %s (%s) uses %q, which the task prompt does not define", seed, task.ID, task.Template, unknown)
			}
		}
	}
}

// One line of a real language's API, dropped into a template, fails the
// allowlist: the deny list of language names could not see these.
func TestBuiltinAllowlistCatchesLanguageAPIs(t *testing.T) {
	const handler = "handler find(request):\n    term = request.query(\"q\")\n"
	for _, line := range []string{
		`    term = request.args.get("q")`,   // Flask
		`    rows = cursor.execute(sql)`,     // DB-API
		`    rows = db.execute(sql)`,         // a method the prompt does not define
		`    term.execute(sql)`,              // a method on a local
		`    os.system("ls " + term)`,        // C, Python
		`    system(term)`,                   // C, C++, PHP
		`    out = exec.Command("ls", term)`, // Go
		`    Console.WriteLine(term)`,        // C#
		`    out = io.popen(term)`,           // Lua
		`    echo $term`,                     // Bash
		`    std::system(term)`,              // C++
		`    printf("%s", term)`,             // C
		`    obj = unserialize(term)`,        // PHP
		`    x = term.length`,                // a field the prompt does not define
		`    x = term.filename.data`,         // a field of a field
		`    return response(200, globals)`,  // a name nothing assigns
		`    out = shell_exec(term)`,         // PHP
		`    rows = store.find_one("a", {})`, // a near miss of a builtin
		`    out = require("child_process")`, // Node
		`    out = fmt.Sprintf("%s", term)`,  // Go
	} {
		code := handler + line + "\n"
		if len(unknownNames(code)) == 0 {
			t.Errorf("%q passes the builtin allowlist", line)
		}
	}
}

// The prompt parse finds every builtin the templates rely on, so an edit
// that drops one from the prompt fails here before it fails in a task.
func TestBuiltinsParsedFromPrompt(t *testing.T) {
	calls, fields := builtins()
	for _, want := range []string{
		"request.query", "request.json", "request.cookie", "request.file", "request.body",
		"db.query", "store.find", "store.first", "shell", "run_process", "templates.render",
		"eval", "make_function", "deserialize_object", "parse_json", "real_path", "get",
	} {
		if !calls[want] {
			t.Errorf("task prompt does not define %s(", want)
		}
	}
	for _, want := range []string{"filename", "data", "name", "body", "status", "scheme", "host", "port", "path"} {
		if !fields[want] {
			t.Errorf("task prompt does not define .%s", want)
		}
	}
	if len(calls) > 40 || len(fields) > 12 {
		t.Errorf("builtin parse is too broad: %d calls, %d fields", len(calls), len(fields))
	}
}
