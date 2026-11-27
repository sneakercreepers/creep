package report

import (
	"slices"
	"strings"
)

// NotLookedFor is a vulnerability class creep has no sink kind or reader
// class for, so no scan ever looks for it, whatever the language or tier.
// Coverage lists only what a run could look for; without this list a clean
// report on a C repository would read as covering its memory-safety bugs
// (#365, ADR 0034). Class and CWE are IDs; Label is fixed text from this
// file, never from the scanned repository.
type NotLookedFor struct {
	Class string `json:"class"`
	CWE   string `json:"cwe"`
	Label string `json:"-"`
}

// notLookedFor is the one list every format and the README read
// (TestReadmeListsNotLookedFor). A class leaves it only when the planner
// gets a sink kind and the reader a class for it.
var notLookedFor = []NotLookedFor{
	{"memory_safety", "CWE-119", "memory-safety bugs in C, C++ and unsafe Rust, such as buffer overflows, use after free and format strings"},
	{"xss", "CWE-79", "cross-site scripting"},
	{"xxe", "CWE-611", "XML external entities"},
	{"csrf", "CWE-352", "cross-site request forgery"},
	{"open_redirect", "CWE-601", "open redirects"},
	{"idor", "CWE-639", "insecure direct object references"},
	{"missing_auth", "CWE-306", "missing authentication on a route or function"},
	{"broken_auth", "CWE-287", "broken authentication, such as weak session, token or password checks"},
	{"prototype_pollution", "CWE-1321", "prototype pollution"},
	{"weak_crypto", "CWE-327", "weak or misused cryptography"},
	{"race_condition", "CWE-362", "race conditions"},
	{"redos", "CWE-1333", "regular-expression denial of service"},
	{"business_logic", "CWE-840", "business-logic flaws"},
}

// NotLookedForClasses returns the classes creep does not look for, in
// their fixed order.
func NotLookedForClasses() []NotLookedFor {
	return slices.Clone(notLookedFor)
}

// NotLookedForText is the one-line list the text summary, Markdown and
// SARIF print: each label with its CWE.
func NotLookedForText() string {
	parts := make([]string, len(notLookedFor))
	for i, c := range notLookedFor {
		parts[i] = c.Label + " (" + c.CWE + ")"
	}
	return strings.Join(parts, "; ")
}

// classCWE is the CWE of each class creep looks for, for SARIF rule tags.
// A class missing here gets no CWE tag rather than a guessed one.
var classCWE = map[string]string{
	"sqli":                     "CWE-89",
	"nosql_injection":          "CWE-943",
	"command_injection":        "CWE-78",
	"code_injection":           "CWE-94",
	"insecure_deserialization": "CWE-502",
	"path_traversal":           "CWE-22",
	"ssrf":                     "CWE-918",
	"template_injection":       "CWE-1336",
	"hardcoded_secret":         "CWE-798",
	"vulnerable_dependency":    "CWE-1395",
}

// ClassCWE returns the CWE of a class creep looks for, or "".
func ClassCWE(class string) string {
	return classCWE[class]
}
