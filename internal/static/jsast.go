package static

import "strings"

// jsFile holds what route extraction needs from one JavaScript or TypeScript
// file. Strings in it are repository text: they feed Locations and name
// matching, never Graph.
type jsFile struct {
	src []byte
	// imports maps a local name to its module, or module.member for a
	// named import or a destructured require.
	imports map[string]string
	// funcs maps top-level function names (declarations and const
	// bindings of function or arrow expressions) to their definitions.
	funcs map[string]*Node
	// models holds names bound anywhere in the file to a Mongoose model
	// or a MongoDB collection (jsfind.go).
	models  map[string]bool
	express bool // the file imports express
}

func newJSFile(root *Node, src []byte) *jsFile {
	f := &jsFile{src: src, imports: map[string]string{}, funcs: map[string]*Node{}, models: map[string]bool{}}
	walk(root, func(n *Node) bool {
		switch n.Type {
		case "import_statement":
			f.addImport(n)
		case "variable_declarator":
			f.addRequire(n)
			f.addModel(n)
		}
		return true
	})
	for _, n := range root.Children {
		f.addFunc(n)
	}
	for _, q := range f.imports {
		f.express = f.express || q == "express" || strings.HasPrefix(q, "express.")
	}
	return f
}

// addImport records `import a from "m"`, `import * as a from "m"`,
// `import { b as a } from "m"` and TypeScript's `import a = require("m")`.
func (f *jsFile) addImport(stmt *Node) {
	mod, ok := f.module(field(stmt, "source"))
	for _, clause := range stmt.Children {
		switch clause.Type {
		case "import_clause":
			if ok {
				f.importClause(clause, mod)
			}
		case "import_require_clause":
			m, ok := f.module(field(clause, "source"))
			if id := firstOfType(clause, "identifier"); ok && id != nil {
				f.imports[f.text(id)] = m
			}
		}
	}
}

func (f *jsFile) importClause(clause *Node, mod string) {
	for _, c := range clause.Children {
		switch c.Type {
		case "identifier":
			f.imports[f.text(c)] = mod
		case "namespace_import":
			if id := firstOfType(c, "identifier"); id != nil {
				f.imports[f.text(id)] = mod
			}
		case "named_imports":
			for _, spec := range namedChildren(c) {
				name := f.text(field(spec, "name"))
				local := name
				if alias := field(spec, "alias"); alias != nil {
					local = f.text(alias)
				}
				f.imports[local] = mod + "." + name
			}
		}
	}
}

// addRequire records `const a = require("m")`, `const a = require("m").b`
// and `const { b, c: a } = require("m")`.
func (f *jsFile) addRequire(decl *Node) {
	mod, ok := f.requireTarget(field(decl, "value"))
	name := field(decl, "name")
	if !ok || name == nil {
		return
	}
	switch name.Type {
	case "identifier":
		f.imports[f.text(name)] = mod
	case "object_pattern":
		for _, p := range namedChildren(name) {
			switch p.Type {
			case "shorthand_property_identifier_pattern":
				f.imports[f.text(p)] = mod + "." + f.text(p)
			case "pair_pattern":
				if v := field(p, "value"); v != nil && v.Type == "identifier" {
					f.imports[f.text(v)] = mod + "." + f.text(field(p, "key"))
				}
			}
		}
	}
}

// requireTarget resolves `require("m")` and member chains on it.
func (f *jsFile) requireTarget(n *Node) (string, bool) {
	var props []string
	for n != nil && n.Type == "member_expression" {
		props = append(props, f.text(field(n, "property")))
		n = field(n, "object")
	}
	mod, ok := f.requireCall(n)
	if !ok {
		return "", false
	}
	for i := len(props) - 1; i >= 0; i-- {
		mod += "." + props[i]
	}
	return mod, true
}

// requireCall matches `require("m")` with a literal module name.
func (f *jsFile) requireCall(n *Node) (string, bool) {
	if n == nil || n.Type != "call_expression" || f.text(field(n, "function")) != "require" {
		return "", false
	}
	args := field(n, "arguments")
	if args == nil || args.Type != "arguments" || len(namedChildren(args)) != 1 {
		return "", false
	}
	return f.module(namedChildren(args)[0])
}

// module reads a module specifier, dropping the "node:" scheme.
func (f *jsFile) module(n *Node) (string, bool) {
	s, ok := f.literalString(n)
	if !ok || s == "" {
		return "", false
	}
	return strings.TrimPrefix(s, "node:"), true
}

// addFunc records a top-level function a handler may name or call.
func (f *jsFile) addFunc(n *Node) {
	if n.Type == "export_statement" {
		n = field(n, "declaration")
	}
	if n == nil {
		return
	}
	switch n.Type {
	case "function_declaration", "generator_function_declaration":
		f.funcs[f.text(field(n, "name"))] = n
	case "lexical_declaration", "variable_declaration":
		for _, d := range namedChildren(n) {
			name, value := field(d, "name"), field(d, "value")
			if name != nil && name.Type == "identifier" && isFunction(value) {
				f.funcs[f.text(name)] = value
			}
		}
	}
}

// resolve turns a callee into a dotted name. When the callee is a method on
// something that is not an import (a variable, a call result, this), it
// returns the method name with method set.
func (f *jsFile) resolve(n *Node) (name string, method bool) {
	var props []string
	for n != nil && n.Type == "member_expression" {
		props = append(props, f.text(field(n, "property")))
		n = field(n, "object")
	}
	q, imported := f.requireCall(n)
	if n != nil && n.Type == "identifier" {
		q, imported = f.imports[f.text(n)]
		if !imported && len(props) == 0 {
			return f.text(n), false
		}
	}
	if !imported {
		if len(props) == 0 {
			return "", false
		}
		return props[0], true
	}
	for i := len(props) - 1; i >= 0; i-- {
		q += "." + props[i]
	}
	return q, false
}

// localCall reports whether a callee is, or is a member of, a module of the
// repository itself (./db, ../models/User, an @/ or ~/ alias), imported or
// required, or a "#" subpath import; method is the called property, "" for
// the import itself. Such
// a receiver is an unknown object from another file, like a variable.
func (f *jsFile) localCall(n *Node) (method string, ok bool) {
	var props []string
	for n != nil && n.Type == "member_expression" {
		props = append(props, f.text(field(n, "property")))
		n = field(n, "object")
	}
	spec, required := f.requireCall(n)
	if !required {
		if n == nil || n.Type != "identifier" {
			return "", false
		}
		if spec, ok = f.imports[f.text(n)]; !ok {
			return "", false
		}
	}
	if !localModule(spec) {
		return "", false
	}
	if len(props) == 0 {
		return "", true
	}
	return props[0], true
}

// localModule reports whether a module specifier (or module.member) names a
// file of the repository rather than a package: npm names never start with
// "." or "/", "@/" and "~/" are path aliases, not scopes, and "#" starts a
// Node subpath import, which package.json maps inside the package.
func localModule(spec string) bool {
	for _, p := range []string{".", "/", "@/", "~/", "#"} {
		if strings.HasPrefix(spec, p) {
			return true
		}
	}
	return false
}

// imported reports whether an expression is an import or a member of one,
// such as express.json or require("cors").
func (f *jsFile) imported(n *Node) bool {
	for n != nil && n.Type == "member_expression" {
		n = field(n, "object")
	}
	if _, ok := f.requireCall(n); ok {
		return true
	}
	if n == nil || n.Type != "identifier" {
		return false
	}
	_, ok := f.imports[f.text(n)]
	return ok
}

// literalString returns the value of a string, a template without
// substitutions, or a + of them, capped at maxPathBytes. Escapes stay as
// written; the value is for the report and prefix matching only. It walks
// without recursion and copies at most the cap, so a hostile chain of
// concatenations costs linear time.
func (f *jsFile) literalString(n *Node) (string, bool) {
	if n == nil {
		return "", false
	}
	var b strings.Builder
	stack := []*Node{n}
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		switch {
		case n.Type == "string" || n.Type == "template_string":
			if !f.writeFragments(&b, n) {
				return "", false
			}
		case n.Type == "parenthesized_expression" && len(namedChildren(n)) == 1:
			stack = append(stack, namedChildren(n)[0])
		case n.Type == "binary_expression" && f.text(field(n, "operator")) == "+":
			stack = append(stack, field(n, "right"), field(n, "left"))
			if stack[len(stack)-1] == nil || stack[len(stack)-2] == nil {
				return "", false
			}
		default:
			return "", false
		}
	}
	return b.String(), true
}

// writeFragments appends a string's text up to maxPathBytes; false means a
// template substitution.
func (f *jsFile) writeFragments(b *strings.Builder, n *Node) bool {
	for _, c := range n.Children {
		switch c.Type {
		case "template_substitution":
			return false
		case "string_fragment":
			if room := maxPathBytes - b.Len(); room > 0 {
				b.WriteString(capText(f.text(c), room))
			}
		case "escape_sequence":
			if room := maxPathBytes - b.Len(); room > 0 {
				b.WriteString(capText(cookJS(f.text(c)), room))
			}
		}
	}
	return true
}

// text returns n's source with identifier escapes decoded, so get spelled
// with a \u escape reads as get, as JavaScript reads it (#259). Literal
// text, whose escapes literalString decodes, stays as written.
func (f *jsFile) text(n *Node) string {
	s := nodeText(f.src, n)
	if n == nil || jsLiteralTypes[n.Type] {
		return s
	}
	return cookJS(s)
}

var jsLiteralTypes = map[string]bool{
	"string": true, "string_fragment": true, "escape_sequence": true, "template_string": true,
	"regex": true, "regex_pattern": true, "comment": true, "jsx_text": true,
}

// isFunction reports whether n is a function or arrow expression.
func isFunction(n *Node) bool {
	if n == nil {
		return false
	}
	switch n.Type {
	case "arrow_function", "function_expression", "function", "generator_function":
		return true
	}
	return false
}

func firstOfType(n *Node, typ string) *Node {
	for _, c := range n.Children {
		if c.Type == typ {
			return c
		}
	}
	return nil
}
