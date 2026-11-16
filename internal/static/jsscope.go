package static

// maxNameBindings caps the bindings kept per receiver name. Past it the name
// resolves to no receiver, so it claims no auth (fails closed).
const maxNameBindings = 256

// scopeRange is the byte range of a function body or of the whole file.
type scopeRange struct{ start, end uint32 }

func (s scopeRange) contains(pos uint32) bool { return s.start <= pos && pos < s.end }

func (s scopeRange) width() uint32 { return s.end - s.start }

// binding is one declaration or assignment of a receiver's name. recv is nil
// when the name holds something else there (a parameter, another value),
// which shadows an outer receiver.
type binding struct {
	scope  scopeRange
	recv   *jsReceiver
	assign bool // an assignment, not a declaration
}

// collectBindings finds express() and Router() receivers by declaration,
// then every other binding of their names, so a reference resolves to the
// receiver declared in its innermost enclosing function. Function scope is
// the unit: let and const in two blocks of one function share it, which only
// makes the receivers ambiguous.
func (x *jsExtraction) collectBindings(root *Node) {
	walkScopes(root, x.receiverBinding)
	if len(x.bind) == 0 {
		return
	}
	walkScopes(root, x.shadowBinding)
	for _, bs := range x.bind {
		markAmbiguous(bs)
	}
}

func (x *jsExtraction) receiverBinding(n *Node, s scopeRange) {
	switch n.Type {
	case "variable_declarator":
		if name := field(n, "name"); name != nil && name.Type == "identifier" && x.constructs(field(n, "value")) {
			x.addBinding(x.file.text(name), binding{scope: s, recv: newReceiver()})
		}
	case "assignment_expression":
		if left := field(n, "left"); left != nil && left.Type == "identifier" && x.constructs(field(n, "right")) {
			x.addBinding(x.file.text(left), binding{scope: s, recv: newReceiver(), assign: true})
		}
	}
}

// shadowBinding records the other bindings of receiver names: values that
// are not receivers, patterns, parameters, catch and loop variables and
// function or class names.
func (x *jsExtraction) shadowBinding(n *Node, s scopeRange) {
	switch n.Type {
	case "variable_declarator":
		if field(n, "value") != nil && !x.constructs(field(n, "value")) {
			x.shadowAll(field(n, "name"), s, false)
		}
	case "assignment_expression":
		if !x.constructs(field(n, "right")) {
			x.shadowAll(field(n, "left"), s, true)
		}
	case "formal_parameters":
		x.shadowAll(n, s, false)
	case "for_in_statement":
		x.shadowAll(field(n, "left"), s, true)
	case "function_declaration", "generator_function_declaration", "class_declaration":
		x.shadowAll(field(n, "name"), s, false)
	case "identifier":
		if n.Field == "parameter" { // arrow `x => ...` and catch (x)
			x.shadowAll(n, s, false)
		}
	}
}

func (x *jsExtraction) shadowAll(n *Node, s scopeRange, assign bool) {
	if n == nil || n.Type == "member_expression" || n.Type == "subscript_expression" {
		return
	}
	walk(n, func(c *Node) bool {
		if c.Type == "identifier" || c.Type == "shorthand_property_identifier_pattern" {
			if name := x.file.text(c); x.bind[name] != nil {
				x.addBinding(name, binding{scope: s, assign: assign})
			}
		}
		return true
	})
}

func (x *jsExtraction) addBinding(name string, b binding) {
	if x.overloaded[name] {
		return
	}
	if len(x.bind[name]) == maxNameBindings {
		x.overloaded[name] = true
		return
	}
	x.bind[name] = append(x.bind[name], b)
}

// markAmbiguous: a receiver whose name is bound twice in its scope, or a
// name that is ever reassigned, is ambiguous, since which object a
// reference holds depends on control flow.
func markAmbiguous(bs []binding) {
	perScope := map[scopeRange]int{}
	assigned := false
	for _, b := range bs {
		perScope[b.scope]++
		assigned = assigned || b.assign
	}
	for _, b := range bs {
		if b.recv != nil && (perScope[b.scope] > 1 || (assigned && len(bs) > 1)) {
			b.recv.ambiguous = true
		}
	}
}

// receiverAt resolves a name used at pos to the receiver bound in the
// innermost scope around it, or nil.
func (x *jsExtraction) receiverAt(name string, pos uint32) *jsReceiver {
	if x.overloaded[name] {
		return nil
	}
	var best *binding
	for i := range x.bind[name] {
		b := &x.bind[name][i]
		if b.scope.contains(pos) && (best == nil || b.scope.width() < best.scope.width()) {
			best = b
		}
	}
	if best == nil {
		return nil
	}
	return best.recv
}

// receiverRef resolves an expression naming a receiver, or nil.
func (x *jsExtraction) receiverRef(n *Node) *jsReceiver {
	n = unwrapCast(n)
	if n == nil || n.Type != "identifier" {
		return nil
	}
	return x.receiverAt(x.file.text(n), n.StartByte)
}

// constructs reports whether value is express() or express.Router(), also
// through `a = b = express()` and TypeScript casts.
func (x *jsExtraction) constructs(value *Node) bool {
	for value != nil && value.Type == "assignment_expression" {
		value = field(value, "right")
	}
	value = unwrapCast(value)
	if value == nil || value.Type != "call_expression" {
		return false
	}
	callee, method := x.file.resolve(field(value, "function"))
	return !method && (callee == "express" || callee == "express.Router")
}

// walkScopes visits every node with the function scope it sits in; a
// function's own node (and so its name) sits in the enclosing scope.
func walkScopes(root *Node, visit func(*Node, scopeRange)) {
	scopes := []scopeRange{{0, ^uint32(0)}}
	walk(root, func(n *Node) bool {
		for len(scopes) > 1 && n.StartByte >= scopes[len(scopes)-1].end {
			scopes = scopes[:len(scopes)-1]
		}
		visit(n, scopes[len(scopes)-1])
		if isFunction(n) || n.Type == "function_declaration" || n.Type == "generator_function_declaration" || n.Type == "method_definition" {
			scopes = append(scopes, scopeRange{n.StartByte, n.EndByte})
		}
		return true
	})
}

// unwrapCast sees through TypeScript casts (as, satisfies, !, <T>x) and
// parentheses, without recursion.
func unwrapCast(n *Node) *Node {
	for n != nil {
		c := namedChildren(n)
		switch {
		case len(c) == 0:
			return n
		case n.Type == "as_expression" || n.Type == "satisfies_expression" || n.Type == "non_null_expression":
			n = c[0]
		case n.Type == "type_assertion":
			n = c[len(c)-1]
		case n.Type == "parenthesized_expression" && len(c) == 1:
			n = c[0]
		default:
			return n
		}
	}
	return n
}
