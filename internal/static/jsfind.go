package static

// findVerdict is what a ".find" call is: a NoSQL sink, no sink (a callback
// or a literal, as Array.prototype.find takes), or unseen: an argument the
// scan cannot tell apart, which marks the route partial.
type findVerdict int

const (
	findNotFilter findVerdict = iota
	findFilter
	findUnknown
)

// maxAliasDepth bounds how many same-function assignments are followed
// from an argument back to req.
const maxAliasDepth = 4

// modelMethods are the calls that return a MongoDB collection or a Mongoose
// model: mongoose.model("User", schema), db.collection("users").
var modelMethods = map[string]bool{"model": true, "collection": true}

// findKind classifies ".find" by its first argument. On a receiver from a
// module of the repository or an in-file model or collection, any argument
// but a function is a filter. On an unknown receiver, which may be an
// array, an object literal or a value rooted in req is a filter, a function
// or a literal is not, and anything else is unseen.
func (x *jsExtraction) findKind(callee *Node, args []*Node, s *jsScan, local bool) findVerdict {
	if len(args) == 0 {
		return findNotFilter
	}
	first := unwrapCast(args[0])
	switch {
	case isFunction(first) || jsLiteral(first):
		return findNotFilter
	case first.Type == "object" || local || x.modelReceiver(callee):
		return findFilter
	case x.fromRequest(first, s, maxAliasDepth):
		return findFilter
	}
	return findUnknown
}

// jsLiteral reports a primitive literal, which no MongoDB filter is.
func jsLiteral(n *Node) bool {
	switch n.Type {
	case "string", "template_string", "number", "true", "false", "null", "undefined":
		return true
	}
	return false
}

// modelReceiver reports whether the receiver of a method call is a model or
// collection: a call to .model or .collection, or a name bound to one
// anywhere in the file.
func (x *jsExtraction) modelReceiver(callee *Node) bool {
	if callee == nil || callee.Type != "member_expression" {
		return false
	}
	recv := unwrapCast(field(callee, "object"))
	switch {
	case recv == nil:
		return false
	case recv.Type == "identifier":
		return x.file.models[x.file.text(recv)]
	}
	return x.file.modelCall(recv)
}

// modelCall reports a call whose callee is a .model or .collection member.
func (f *jsFile) modelCall(n *Node) bool {
	n = unwrapCast(n)
	if n != nil && n.Type == "await_expression" && len(namedChildren(n)) == 1 {
		n = unwrapCast(namedChildren(n)[0])
	}
	if n == nil || n.Type != "call_expression" {
		return false
	}
	callee := field(n, "function")
	return callee != nil && callee.Type == "member_expression" && modelMethods[f.text(field(callee, "property"))]
}

// addModel records `const User = mongoose.model(...)` and the like.
func (f *jsFile) addModel(decl *Node) {
	name := field(decl, "name")
	if name != nil && name.Type == "identifier" && f.modelCall(field(decl, "value")) {
		f.models[f.text(name)] = true
	}
}

// fromRequest reports whether n reads from the request object: req.query,
// req.body["x"], or a name the scanned function assigns from one. A name
// with several assignments counts if any of them does.
func (x *jsExtraction) fromRequest(n *Node, s *jsScan, depth int) bool {
	n = unwrapCast(n)
	for n != nil && (n.Type == "member_expression" || n.Type == "subscript_expression") {
		n = unwrapCast(field(n, "object"))
	}
	if n == nil || n.Type != "identifier" {
		return false
	}
	name := x.file.text(n)
	if name == "req" || name == "request" {
		return true
	}
	if depth == 0 {
		return false
	}
	for _, v := range s.assigns[name] {
		if x.fromRequest(v, s, depth-1) {
			return true
		}
	}
	return false
}
