package static

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

// jsUses judges every use of a known Express app or router in one file.
type jsUses struct {
	x       *jsExtraction
	parents map[*Node]*Node
	// factories holds the names of functions that return a receiver; each
	// call of one is a use of that receiver.
	factories   map[string]bool
	exported    bool // a receiver is assigned to module.exports or exports.x
	exportsRead bool // module.exports or exports is read back in the file
	escaped     bool
}

// receiverEscapes reports whether a known Express app or router is used in
// first-party code other than in a form the extractor reads (#255
// maintainer decision): passed to a function, stored in an object or an
// array, destructured, parenthesized, reached through .call, .apply, .bind
// or Reflect, returned by a function whose result is used, or exported and
// read back through exports. Any route it reaches that way is invisible, so
// the caller marks the file not evaluated in full. benignUse lists what is
// read.
func (x *jsExtraction) receiverEscapes(root *Node) bool {
	if len(x.bind) == 0 {
		return false
	}
	u := &jsUses{x: x, parents: parentsOf(root), factories: map[string]bool{}}
	walk(root, func(n *Node) bool {
		u.visit(n)
		return !u.escaped
	})
	if !u.escaped && len(u.factories) > 0 {
		walk(root, func(n *Node) bool {
			u.escaped = u.escaped || n.Type == "identifier" && u.factories[x.file.text(n)] && !u.factoryUse(n)
			return !u.escaped
		})
	}
	return u.escaped || u.exported && u.exportsRead
}

func (u *jsUses) visit(n *Node) {
	if exportsRoot(u.x.file, n) && !u.assignedTo(n) {
		u.exportsRead = true
	}
	if n.Type != "identifier" && n.Type != "shorthand_property_identifier" {
		return
	}
	if u.x.receiverAt(u.x.file.text(n), n.StartByte) != nil {
		u.escaped = !u.benignUse(n)
	}
}

// benignUse covers the reads of a receiver that reach no route:
//   - a method call whose result is discarded (app.get(...), app.use(mw));
//     a chained call only from .route, and only when the whole chain is
//     discarded; app.listen, app.enabled, app.disabled, app.path,
//     app.render and app.get(name), which return no app, in any position;
//   - app.locals, app.settings and app.mountpath;
//   - a declaration or assignment of the name;
//   - module.exports = app, exports.x = app (also inside an object literal
//     assigned there), export default app and export { app };
//   - return app, in a named function whose calls are themselves benign
//     (factoryUse);
//   - the argument of .use on a known app or router (a mount) and of the
//     node core http.createServer or https.createServer.
func (u *jsUses) benignUse(n *Node) bool {
	p := u.parents[n]
	if p == nil {
		return false
	}
	if n.Type == "shorthand_property_identifier" {
		return u.exportedObject(p)
	}
	switch p.Type {
	case "pair":
		return n.Field == "value" && u.exportedObject(u.parents[p])
	case "variable_declarator":
		return n.Field == "name"
	case "assignment_expression":
		return n.Field == "left" || n.Field == "right" && u.exportTarget(p)
	case "export_statement", "export_specifier":
		return true
	case "return_statement":
		return u.addFactory(p)
	case "member_expression":
		return n.Field == "object" && u.benignMember(p)
	case "subscript_expression":
		return n.Field == "object" && calledMember(p, u.parents, "call_expression") && u.discarded(u.parents[p])
	case "arguments":
		return u.benignArgument(u.parents[p])
	}
	return false
}

var jsBenignProperties = map[string]bool{"locals": true, "settings": true, "mountpath": true}

// jsValueMethods return a server or a value, never the app or router.
var jsValueMethods = map[string]bool{"listen": true, "enabled": true, "disabled": true, "path": true, "render": true}

func (u *jsUses) benignMember(member *Node) bool {
	prop := u.x.file.text(field(member, "property"))
	if !calledMember(member, u.parents, "call_expression") {
		return jsBenignProperties[prop]
	}
	call := u.parents[member]
	if jsValueMethods[prop] || prop == "get" && len(namedChildren(field(call, "arguments"))) == 1 {
		return true
	}
	if prop == "route" {
		call = u.chainTop(call)
	}
	return u.discarded(call)
}

// chainTop climbs app.route(p).get(h).post(h) to its last call.
func (u *jsUses) chainTop(call *Node) *Node {
	for {
		member := u.parents[call]
		if member == nil || member.Type != "member_expression" || call.Field != "object" || !calledMember(member, u.parents, "call_expression") {
			return call
		}
		call = u.parents[member]
	}
}

// discarded reports whether a call's result is thrown away, so the app or
// router a method returns reaches nothing else.
func (u *jsUses) discarded(call *Node) bool {
	p := u.parents[call]
	return p != nil && p.Type == "expression_statement"
}

var jsHTTPServers = map[string]bool{
	"http.createServer": true, "https.createServer": true,
	"node:http.createServer": true, "node:https.createServer": true,
}

func (u *jsUses) benignArgument(call *Node) bool {
	if call == nil || call.Type != "call_expression" {
		return false
	}
	fn := field(call, "function")
	if fn == nil || fn.Type != "member_expression" {
		return false
	}
	obj := field(fn, "object")
	if u.x.file.text(field(fn, "property")) == "use" {
		return obj != nil && obj.Type == "identifier" && u.x.receiverAt(u.x.file.text(obj), obj.StartByte) != nil
	}
	name, _ := u.x.file.resolve(fn)
	return jsHTTPServers[name]
}
