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
	funcs   map[string]*Node
	express bool // the file imports express
}

func newJSFile(root *Node, src []byte) *jsFile {
	f := &jsFile{src: src, imports: map[string]string{}, funcs: map[string]*Node{}}
	walk(root, func(n *Node) bool {
		switch n.Type {
		case "import_statement":
			f.addImport(n)
		case "variable_declarator":
			f.addRequire(n)
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
		case "string_fragment", "escape_sequence":
			if room := maxPathBytes - b.Len(); room > 0 {
				b.WriteString(capText(f.text(c), room))
			}
		}
	}
	return true
}

func (f *jsFile) text(n *Node) string { return nodeText(f.src, n) }

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
