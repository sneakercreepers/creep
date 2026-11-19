package redact

import (
	"strings"
	"testing"
)

// The reader once skipped indented lines and every key after an allowlist
// block, so a rule key placed there, or indented by mistake, was dropped
// without a word (issue #70). Each case names the line and the reason.
func TestParseRulesRejectsMisplacedKeys(t *testing.T) {
	const rule = "[[rules]]\nid = \"a\"\nregex = '''abc'''\n"
	tests := []struct {
		name, toml, want string
	}{
		{"indented key", rule + "  keywords = [\"abc\"]\n", "line 4: indented line outside an array"},
		{"tab-indented key", rule + "\tsecretGroup = 1\n", "line 4: indented line outside an array"},
		{"indented comment", rule + "  # note\n", "line 4: indented line"},
		{"regex after allowlist", rule + "[[rules.allowlists]]\nregexes = ['''x''']\nregex = '''def'''\n", "line 6: rule key regex after an allowlist block"},
		{"keywords after allowlist", rule + "[[rules.allowlists]]\nkeywords = [\"abc\"]\n", "line 5: rule key keywords after an allowlist block"},
		{"secretGroup after allowlist", rule + "[[rules.allowlists]]\nsecretGroup = 1\n", "rule key secretGroup after an allowlist block"},
		{"id after allowlist", rule + "[[rules.allowlists]]\nid = \"b\"\n", "rule key id after an allowlist block"},
		{"rule key in global allowlist", "[allowlist]\nregex = '''x'''\n", "line 2: unknown key regex in [allowlist]"},
		{"unknown rule key", rule + "regexes = ['''x''']\n", "line 4: unknown key regexes in [[rules]]"},
		{"misspelled rule key", rule + "secretgroup = 1\n", "unknown key secretgroup"},
		{"unknown top key", "extend = true\n", "unknown key extend in the top level"},
		{"duplicate rule key", rule + "regex = '''def'''\n", "line 4: duplicate key regex"},
		{"duplicate keywords", rule + "keywords = [\"a\"]\nkeywords = [\n    \"b\",\n]\n", "duplicate key keywords"},
		{"rule allowlist before a rule", "[[rules.allowlists]]\n", "outside a rule"},
		{"rule allowlist after global", "[allowlist]\n[[rules.allowlists]]\n", "outside a rule"},
		{"stray closing bracket", rule + "]\n", "unsupported syntax"},
		{"unclosed array", rule + "keywords = [\n    \"a\",", "array keywords is not closed"},
		{"unindented element", rule + "keywords = [\n\"a\",\n]\n", "want an indented element"},
		{"blank line in array", rule + "keywords = [\n\n]\n", "want an indented element"},
		{"key inside allowlist array", rule + "[[rules.allowlists]]\nregexes = [\n    regex = 'x'\n]\n", "want a quoted element"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			specs, err := parseRules([]byte(tc.toml))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("parseRules error = %v (specs %+v), want %q", err, specs, tc.want)
			}
		})
	}
}

// The keys the reader drops on purpose (description, entropy, path and the
// allowlist keys) still parse, in every table the embedded files use them in.
func TestParseRulesAcceptsIgnoredKeys(t *testing.T) {
	toml := "title = \"t\"\nminVersion = \"v8\"\n" +
		"[allowlist]\ndescription = \"d\"\nregexTarget = \"line\"\nstopwords = [\"a\"]\npaths = [\n    '''x''','''y''',\n]\n" +
		"[[rules]]\nid = \"r\"\ndescription = \"d\"\nregex = '''abc'''\nentropy = 3.5\npath = '''\\.php$'''\nkeywords = [\"abc\"]\n" +
		"[[rules.allowlists]]\ncondition = \"AND\"\ndescription = \"d\"\npaths = ['''p''']\n" +
		"[[rules.allowlists]]\nregexes = [\n    \"q\",\n]\n" +
		"[[rules]]\nid = \"s\"\nregex = '''def'''\n"
	specs, err := parseRules([]byte(toml))
	if err != nil {
		t.Fatal(err)
	}
	if len(specs) != 2 || specs[0].Regex != "abc" || specs[1].ID != "s" {
		t.Fatalf("specs = %+v, want rules r and s", specs)
	}
}
