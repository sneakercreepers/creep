package static

import "strings"

// addFactory records the named function that holds a `return app`, so its
// calls are judged as uses of the app (#255 tester cycle 6). A return from
// an anonymous function or a method has no name to follow and escapes.
func (u *jsUses) addFactory(ret *Node) bool {
	name := u.enclosingFunctionName(ret)
	if name != "" {
		u.factories[name] = true
	}
	return name != ""
}

func (u *jsUses) enclosingFunctionName(n *Node) string {
	for n = u.parents[n]; n != nil; n = u.parents[n] {
		switch n.Type {
		case "function_declaration", "generator_function_declaration":
			return u.x.file.text(field(n, "name"))
		case "function_expression", "function", "arrow_function":
			p := u.parents[n]
			if p == nil || p.Type != "variable_declarator" || n.Field != "value" {
				return ""
			}
			name := field(p, "name")
			if name == nil || name.Type != "identifier" {
				return ""
			}
			return u.x.file.text(name)
		case "method_definition", "class_body", "program":
			return ""
		}
	}
	return ""
}

// factoryUse reports whether a name of a function that returns a receiver
// sits where it reaches no route: its own declaration, or a call whose
// result is discarded, exported or only listened on (mk().listen(3000)).
// mk().get(...), const a = mk() and passing mk itself escape.
func (u *jsUses) factoryUse(n *Node) bool {
	p := u.parents[n]
	switch {
	case p == nil:
		return false
	case p.Type == "function_declaration" || p.Type == "generator_function_declaration" || p.Type == "variable_declarator":
		return n.Field == "name"
	case p.Type != "call_expression" || n.Field != "function":
		return false
	}
	q := u.parents[p]
	switch {
	case q == nil:
		return false
	case q.Type == "expression_statement" || q.Type == "export_statement":
		return true
	case q.Type == "assignment_expression" && p.Field == "right" && u.exportTarget(q):
		return true
	case q.Type == "member_expression" && p.Field == "object":
		return u.x.file.text(field(q, "property")) == "listen" && calledMember(q, u.parents, "call_expression")
	}
	return false
}

// exportTarget reports whether an assignment stores into module.exports or
// exports.x, and records that a receiver left the file that way.
func (u *jsUses) exportTarget(assign *Node) bool {
	ok := exportsTarget(u.x.file.text(field(assign, "left")))
	u.exported = u.exported || ok
	return ok
}

// exportedObject reports whether obj is an object literal assigned to
// module.exports or exports.x, as in module.exports = { app }.
func (u *jsUses) exportedObject(obj *Node) bool {
	if obj == nil || obj.Type != "object" {
		return false
	}
	p := u.parents[obj]
	return p != nil && p.Type == "assignment_expression" && obj.Field == "right" && u.exportTarget(p)
}

func exportsTarget(left string) bool {
	return left == "module.exports" || strings.HasPrefix(left, "module.exports.") || strings.HasPrefix(left, "exports.")
}

// exportsRoot reports whether n is the identifier exports or the member
// module.exports: an exported app read back through either
// (exports.app.get(...)) is a use static does not follow.
func exportsRoot(f *jsFile, n *Node) bool {
	switch n.Type {
	case "identifier":
		return f.text(n) == "exports"
	case "member_expression":
		return f.text(field(n, "object")) == "module" && f.text(field(n, "property")) == "exports"
	}
	return false
}

// assignedTo reports whether n heads the left side of an assignment, as in
// module.exports.app = app, which writes the export rather than reading it.
func (u *jsUses) assignedTo(n *Node) bool {
	for {
		p := u.parents[n]
		switch {
		case p == nil:
			return false
		case (p.Type == "member_expression" || p.Type == "subscript_expression") && n.Field == "object":
			n = p
		default:
			return p.Type == "assignment_expression" && n.Field == "left"
		}
	}
}
