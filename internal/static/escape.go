package static

import "strings"

// parentsOf maps every node of a tree to its parent, for the receiver
// escape checks that judge a name by where it sits.
func parentsOf(root *Node) map[*Node]*Node {
	parents := map[*Node]*Node{}
	walk(root, func(n *Node) bool {
		for _, c := range n.Children {
			parents[c] = n
		}
		return true
	})
	return parents
}

// calledMember reports whether member, an attribute or member access, is
// the callee of a call: p.Field is "function" and its parent is a call.
func calledMember(member *Node, parents map[*Node]*Node, call string) bool {
	gp := parents[member]
	return gp != nil && gp.Type == call && member.Field == "function"
}

// receiverEscapes reports whether a known Express app or router is used in
// first-party code other than in a form the extractor reads (#255
// maintainer decision): passed to a function, stored in an object or an
// array, destructured, parenthesized, reached through .call, .apply, .bind
// or Reflect. Any route it reaches that way is invisible, so the caller
// marks the file not evaluated in full. jsBenignUses lists what is read.
func (x *jsExtraction) receiverEscapes(root *Node) bool {
	if len(x.bind) == 0 {
		return false
	}
	parents := parentsOf(root)
	escaped := false
	walk(root, func(n *Node) bool {
		if escaped || n.Type != "identifier" && n.Type != "shorthand_property_identifier" {
			return !escaped
		}
		if x.receiverAt(x.file.text(n), n.StartByte) == nil {
			return true
		}
		escaped = !x.benignUse(n, parents)
		return !escaped
	})
	return escaped
}

// jsBenignUses are the reads of a receiver that reach no route: any method
// call (app.get(...), app.use(...), app.listen(...); a call whose result is
// chained is read only for .route), app.locals, app.settings and
// app.mountpath, a declaration or assignment, module.exports = app,
// exports.x = app (also inside an object literal assigned there), export
// default app and export { app }, return app, an
// argument of a .use call (a mount) and of http.createServer or
// https.createServer.
func (x *jsExtraction) benignUse(n *Node, parents map[*Node]*Node) bool {
	p := parents[n]
	if p == nil {
		return false
	}
	if n.Type == "shorthand_property_identifier" {
		return x.exportedObject(p, parents)
	}
	switch p.Type {
	case "pair":
		return n.Field == "value" && x.exportedObject(parents[p], parents)
	case "variable_declarator":
		return n.Field == "name"
	case "assignment_expression":
		return n.Field == "left" || n.Field == "right" && exportsTarget(x.file.text(field(p, "left")))
	case "export_statement", "export_specifier", "return_statement":
		return true
	case "member_expression":
		return n.Field == "object" && x.benignMember(p, parents)
	case "subscript_expression":
		return n.Field == "object" && calledMember(p, parents, "call_expression")
	case "arguments":
		return x.benignArgument(parents[p])
	}
	return false
}

var jsBenignProperties = map[string]bool{"locals": true, "settings": true, "mountpath": true}

func (x *jsExtraction) benignMember(member *Node, parents map[*Node]*Node) bool {
	prop := x.file.text(field(member, "property"))
	if !calledMember(member, parents, "call_expression") {
		return jsBenignProperties[prop]
	}
	call := parents[member]
	outer := parents[call]
	chained := outer != nil && outer.Type == "member_expression" && call.Field == "object"
	return !chained || prop == "route"
}

func (x *jsExtraction) benignArgument(call *Node) bool {
	if call == nil || call.Type != "call_expression" {
		return false
	}
	fn := field(call, "function")
	if fn == nil || fn.Type != "member_expression" {
		return false
	}
	prop := x.file.text(field(fn, "property"))
	return prop == "use" || prop == "createServer" && isHTTPModule(x.file.text(field(fn, "object")))
}

func isHTTPModule(name string) bool { return name == "http" || name == "https" }

// exportedObject reports whether obj is an object literal assigned to
// module.exports or exports.x, as in module.exports = { app }.
func (x *jsExtraction) exportedObject(obj *Node, parents map[*Node]*Node) bool {
	if obj == nil || obj.Type != "object" {
		return false
	}
	p := parents[obj]
	return p != nil && p.Type == "assignment_expression" && obj.Field == "right" && exportsTarget(x.file.text(field(p, "left")))
}

func exportsTarget(left string) bool {
	return left == "module.exports" || strings.HasPrefix(left, "module.exports.") || strings.HasPrefix(left, "exports.")
}
