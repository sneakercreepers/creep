package redact

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// ruleSpec is the part of a gitleaks rule creep uses.
type ruleSpec struct {
	ID          string
	Regex       string
	SecretGroup int
	Keywords    []string // lowercase; the rule only runs when one occurs
	file        string   // the rules file it came from, for error messages
}

// section is the table the reader is in; only [[rules]] keys are used.
type section int

const (
	sectionTop section = iota
	sectionRule
	sectionRuleAllowlist // [[rules.allowlists]] of the last rule
	sectionAllowlist     // the global [allowlist]
)

var sectionNames = map[section]string{
	sectionTop:           "the top level",
	sectionRule:          "[[rules]]",
	sectionRuleAllowlist: "[[rules.allowlists]]",
	sectionAllowlist:     "[allowlist]",
}

// sectionKeys are the keys each table may hold: those the vendored and local
// files use. Any other key is an error, so a typo or an upstream format
// change cannot drop a rule's settings silently.
var sectionKeys = map[section][]string{
	sectionTop:           {"title", "minVersion"},
	sectionRule:          {"id", "description", "regex", "secretGroup", "keywords", "entropy", "path"},
	sectionRuleAllowlist: {"description", "condition", "paths", "regexes", "regexTarget", "stopwords"},
	sectionAllowlist:     {"description", "paths", "regexes", "regexTarget", "stopwords"},
}

// ruleKeys are the rule keys creep reads. One after an allowlist block
// belongs to that allowlist in TOML, which an author meaning to set the rule
// would not see, so the reader names that mistake.
var ruleKeys = map[string]bool{"id": true, "regex": true, "secretGroup": true, "keywords": true}

var (
	keyLine   = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9]*) = (.*)$`)
	ruleIDRe  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
	maxRuleID = 80
)

// tomlReader reads the rules file line by line.
type tomlReader struct {
	rules []ruleSpec
	sec   section
	seen  map[string]bool // keys already set in the current table
	array string          // key of the open multi-line array, "" when none
}

// parseRules reads the subset of TOML that the gitleaks default config uses.
// Anything outside that subset is an error, so an upstream format change fails
// the tests instead of silently dropping rules: an unknown or repeated key, a
// rule key after an allowlist block, and an indented line outside an array.
func parseRules(data []byte) ([]ruleSpec, error) {
	p := &tomlReader{seen: map[string]bool{}}
	for i, line := range strings.Split(string(data), "\n") {
		if err := p.line(strings.TrimSuffix(line, "\r")); err != nil {
			return nil, fmt.Errorf("line %d: %w", i+1, err)
		}
	}
	if p.array != "" {
		return nil, fmt.Errorf("array %s is not closed", p.array)
	}
	return p.rules, validateSpecs(p.rules)
}

func (p *tomlReader) line(line string) error {
	switch {
	case p.array != "":
		return p.arrayLine(line)
	case line == "" || strings.HasPrefix(line, "#"):
		return nil
	case strings.HasPrefix(line, "["):
		return p.table(line)
	case strings.HasPrefix(line, " "), strings.HasPrefix(line, "\t"):
		return fmt.Errorf("indented line outside an array: %q", line)
	}
	m := keyLine.FindStringSubmatch(line)
	if m == nil {
		return fmt.Errorf("unsupported syntax %q", line)
	}
	return p.key(m[1], m[2])
}

// table starts the table a header line names.
func (p *tomlReader) table(line string) error {
	switch line {
	case "[[rules]]":
		p.rules = append(p.rules, ruleSpec{})
		p.enter(sectionRule)
	case "[[rules.allowlists]]":
		if p.sec != sectionRule && p.sec != sectionRuleAllowlist {
			return fmt.Errorf("%s outside a rule", line)
		}
		p.enter(sectionRuleAllowlist)
	case "[allowlist]":
		p.enter(sectionAllowlist)
	default:
		return fmt.Errorf("unsupported table %q", line)
	}
	return nil
}

func (p *tomlReader) enter(sec section) {
	p.sec = sec
	p.seen = map[string]bool{}
}

// key checks one key line against its table and, in a rule, sets it.
func (p *tomlReader) key(key, value string) error {
	if err := p.allowKey(key); err != nil {
		return err
	}
	p.seen[key] = true
	if value == "[" {
		p.array = key
		return nil
	}
	if p.sec != sectionRule {
		return nil
	}
	return setRuleKey(&p.rules[len(p.rules)-1], key, value)
}

// allowKey rejects a key its table does not hold, or holds already.
func (p *tomlReader) allowKey(key string) error {
	switch {
	case p.seen[key]:
		return fmt.Errorf("duplicate key %s in %s", key, sectionNames[p.sec])
	case slices.Contains(sectionKeys[p.sec], key):
		return nil
	case p.sec == sectionRuleAllowlist && ruleKeys[key]:
		return fmt.Errorf("rule key %s after an allowlist block: it would set the allowlist, not the rule", key)
	}
	return fmt.Errorf("unknown key %s in %s", key, sectionNames[p.sec])
}

// arrayLine reads one indented element, or the closing bracket, of a
// multi-line array. Only a rule's keywords are kept; other arrays belong to
// allowlists and are checked for shape only.
func (p *tomlReader) arrayLine(line string) error {
	if line == "]" {
		p.array = ""
		return nil
	}
	elem := strings.TrimSuffix(strings.TrimLeft(line, " "), ",")
	if !strings.HasPrefix(line, " ") || elem == "" {
		return fmt.Errorf("%s: want an indented element, got %q", p.array, line)
	}
	if p.sec == sectionRule && p.array == "keywords" {
		kw, err := basicString(elem)
		if err != nil {
			return fmt.Errorf("keywords: %w", err)
		}
		r := &p.rules[len(p.rules)-1]
		r.Keywords = append(r.Keywords, strings.ToLower(kw))
		return nil
	}
	// Allowlist arrays may hold several elements per line; each starts with
	// a quote, so a stray key line cannot pass as an element.
	if elem[0] != '"' && elem[0] != '\'' {
		return fmt.Errorf("%s: want a quoted element, got %q", p.array, line)
	}
	return nil
}

func setRuleKey(r *ruleSpec, key, value string) error {
	var err error
	switch key {
	case "id":
		r.ID, err = basicString(value)
	case "regex":
		r.Regex, err = literalString(value)
	case "secretGroup":
		r.SecretGroup, err = strconv.Atoi(value)
	case "keywords":
		r.Keywords, err = stringArray(value)
	}
	if err != nil {
		return fmt.Errorf("key %s: %w", key, err)
	}
	return nil
}

// stringArray reads a single-line ["a", "b"] array. Elements cannot contain
// quotes (basicString rejects them), so splitting on ", " is unambiguous.
func stringArray(v string) ([]string, error) {
	if len(v) < 2 || v[0] != '[' || v[len(v)-1] != ']' {
		return nil, fmt.Errorf("want a single-line array, got %q", v)
	}
	var out []string
	for _, part := range strings.Split(v[1:len(v)-1], ", ") {
		s, err := basicString(part)
		if err != nil {
			return nil, err
		}
		out = append(out, strings.ToLower(s))
	}
	return out, nil
}

// basicString accepts a "..." string without escapes; rule ids never need them.
func basicString(v string) (string, error) {
	if len(v) < 2 || v[0] != '"' || v[len(v)-1] != '"' {
		return "", fmt.Errorf("want a quoted string, got %q", v)
	}
	s := v[1 : len(v)-1]
	if strings.ContainsAny(s, `"\`) {
		return "", fmt.Errorf("escapes are not supported in %q", v)
	}
	return s, nil
}

// literalString accepts a single-line ”'...”' string, taken verbatim.
func literalString(v string) (string, error) {
	const q = "'''"
	if len(v) < 2*len(q) || !strings.HasPrefix(v, q) || !strings.HasSuffix(v, q) {
		return "", fmt.Errorf("want a single-line ''' string, got %q", v)
	}
	s := v[len(q) : len(v)-len(q)]
	if strings.Contains(s, q) {
		return "", fmt.Errorf("nested ''' in %q", v)
	}
	return s, nil
}

func validateSpecs(rules []ruleSpec) error {
	seen := make(map[string]bool, len(rules))
	for i, r := range rules {
		if !ruleIDRe.MatchString(r.ID) || len(r.ID) > maxRuleID {
			return fmt.Errorf("rule %d: invalid id %q", i+1, r.ID)
		}
		if seen[r.ID] {
			return fmt.Errorf("rule %s: duplicate id", r.ID)
		}
		seen[r.ID] = true
		if r.SecretGroup < 0 {
			return fmt.Errorf("rule %s: negative secretGroup", r.ID)
		}
	}
	return nil
}
