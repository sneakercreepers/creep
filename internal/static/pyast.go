package static

import "strings"

// pyFile holds what route extraction needs from one Python file. Strings in
// it are repository text: they feed Locations and name matching, never Graph.
type pyFile struct {
	src     []byte
	imports map[string]string // local name -> dotted module path
	// funcs maps module-level function names to their definitions, for
	// one-level helper lookups.
	funcs map[string]*Node
	// nonlocals holds names any nested function rebinds with `nonlocal`,
	// so an enclosing function never treats them as constant.
	nonlocals      map[string]bool
	flask, fastapi bool // the file imports the framework
}

func newPyFile(root *Node, src []byte) *pyFile {
	f := &pyFile{src: src, imports: map[string]string{}, funcs: map[string]*Node{}, nonlocals: map[string]bool{}}
	walk(root, func(n *Node) bool {
		switch n.Type {
		case "import_statement":
			f.addImport(n, "")
		case "import_from_statement":
			if mod := field(n, "module_name"); mod != nil && mod.Type == "dotted_name" {
				f.addImport(n, f.dotted(mod))
			}
		case "nonlocal_statement":
			for _, c := range namedChildren(n) {
				f.nonlocals[f.text(c)] = true
			}
		}
		return true
	})
	for _, n := range root.Children {
		if def := functionDef(n); def != nil {
			f.funcs[f.text(field(def, "name"))] = def
		}
	}
	for _, q := range f.imports {
		f.flask = f.flask || q == "flask" || strings.HasPrefix(q, "flask.")
		f.fastapi = f.fastapi || q == "fastapi" || strings.HasPrefix(q, "fastapi.")
	}
	return f
}

// addImport records the names an import binds. from is "" for `import x`.
func (f *pyFile) addImport(stmt *Node, from string) {
	for _, c := range stmt.Children {
		if c.Field != "name" {
			continue
		}
		target, local := c, ""
		if c.Type == "aliased_import" {
			target, local = field(c, "name"), f.text(field(c, "alias"))
		}
		if target == nil || target.Type != "dotted_name" {
			continue
		}
		path := f.dotted(target)
		switch {
		case from != "":
			path = from + "." + path
		case local == "":
			// `import os.path` binds "os" to the os module.
			path, _, _ = strings.Cut(path, ".")
		}
		if local == "" {
			local = path[strings.LastIndexByte(path, '.')+1:]
		}
		f.imports[local] = path
	}
}

// resolve turns a callee or decorator expression into a dotted name. When the
// expression is a method on something that is not an import (a variable, a
// call result), it returns the method name with method set.
func (f *pyFile) resolve(n *Node) (name string, method bool) {
	var attrs []string
	for n != nil && n.Type == "attribute" {
		attrs = append(attrs, f.text(field(n, "attribute")))
		n = field(n, "object")
	}
	if n == nil || n.Type != "identifier" {
		if len(attrs) == 0 {
			return "", false
		}
		return attrs[0], true
	}
	root := f.text(n)
	q, imported := f.imports[root]
	if !imported {
		if len(attrs) == 0 {
			return root, false
		}
		return attrs[0], true
	}
	for i := len(attrs) - 1; i >= 0; i-- {
		q += "." + attrs[i]
	}
	return q, false
}

// literalString returns the value of a string made only of literal parts.
// Escape sequences stay as written; the value is for the report only.
func (f *pyFile) literalString(n *Node) (string, bool) {
	if n == nil {
		return "", false
	}
	switch n.Type {
	case "string":
		var b strings.Builder
		for _, c := range n.Children {
			switch c.Type {
			case "interpolation":
				return "", false
			case "string_content":
				b.WriteString(f.text(c))
			}
		}
		return b.String(), true
	case "concatenated_string":
		var b strings.Builder
		for _, c := range namedChildren(n) {
			s, ok := f.literalString(c)
			if !ok {
				return "", false
			}
			b.WriteString(s)
		}
		return b.String(), true
	}
	return "", false
}

func (f *pyFile) dotted(n *Node) string {
	var parts []string
	for _, c := range n.Children {
		if c.Type == "identifier" {
			parts = append(parts, f.text(c))
		}
	}
	return strings.Join(parts, ".")
}

// text returns the source of n, or "" when n is nil or out of range.
func (f *pyFile) text(n *Node) string {
	if n == nil || n.StartByte > n.EndByte || int(n.EndByte) > len(f.src) {
		return ""
	}
	return string(f.src[n.StartByte:n.EndByte])
}

// functionDef returns the function a module-level statement defines, if any.
func functionDef(n *Node) *Node {
	if n.Type == "decorated_definition" {
		n = field(n, "definition")
	}
	if n == nil || n.Type != "function_definition" {
		return nil
	}
	return n
}

func field(n *Node, name string) *Node {
	if n == nil {
		return nil
	}
	for _, c := range n.Children {
		if c.Field == name {
			return c
		}
	}
	return nil
}

// namedChildren skips punctuation and comments.
func namedChildren(n *Node) []*Node {
	var out []*Node
	for _, c := range n.Children {
		if c.Named && !c.Extra {
			out = append(out, c)
		}
	}
	return out
}

// walk visits n and its descendants in preorder without recursion, so a
// deeply nested hostile file cannot exhaust the stack. visit returns false
// to skip a node's children.
func walk(n *Node, visit func(*Node) bool) {
	stack := []*Node{n}
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if !visit(n) {
			continue
		}
		for i := len(n.Children) - 1; i >= 0; i-- {
			stack = append(stack, n.Children[i])
		}
	}
}
