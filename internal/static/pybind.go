package static

// bodyScan is one pass over a function body.
type bodyScan struct {
	calls []*Node
	// assigns maps a name to the right-hand sides of its simple
	// `name = value` assignments, in source order.
	assigns map[string][]*Node
	// dynamic holds names bound any other way (tuple target, for, with,
	// except, walrus, augmented assignment, import, parameter, global,
	// nonlocal, match capture, nested def or class). They never count as
	// constant.
	dynamic map[string]bool
	// names memoizes constantName per name.
	names map[string]nameState
}

// nameState is the memoized DynamicArg verdict for one name.
type nameState uint8

const (
	nameBusy nameState = iota + 1 // being evaluated; a cycle reads as dynamic
	nameConst
	nameDynamic
)

// scan collects calls and name bindings in a body once, skipping nested
// function and class bodies so no node is scanned for two handlers.
func (x *pyExtraction) scan(def *Node) bodyScan {
	if s, ok := x.scans[def]; ok {
		return s
	}
	s := bodyScan{assigns: map[string][]*Node{}, dynamic: map[string]bool{}, names: map[string]nameState{}}
	x.bindAll(s, field(def, "parameters"))
	if body := field(def, "body"); body != nil {
		walk(body, func(n *Node) bool { return x.scanNode(&s, n) })
	}
	x.scans[def] = s
	return s
}

// scanNode records what one node binds and whether to walk its children.
func (x *pyExtraction) scanNode(s *bodyScan, n *Node) bool {
	switch n.Type {
	case "function_definition", "class_definition":
		x.bindAll(*s, field(n, "name"))
		x.scanHeader(s, n)
		return false // the body is its own scope; decorators were walked
	case "type_alias_statement":
		x.bindAll(*s, n)
	case "call":
		s.calls = append(s.calls, n)
	case "assignment":
		x.addAssign(*s, n)
	case "augmented_assignment", "for_statement", "for_in_clause":
		x.bindAll(*s, field(n, "left"))
	case "as_pattern":
		x.bindAll(*s, field(n, "alias"))
	case "named_expression":
		x.bindAll(*s, field(n, "name"))
	case "global_statement", "nonlocal_statement", "import_statement", "import_from_statement":
		x.bindAll(*s, n)
	case "case_clause":
		for _, c := range n.Children {
			if c.Type == "case_pattern" {
				x.bindAll(*s, c)
			}
		}
	}
	return true
}

// scanHeader walks the parts of a nested def or class that run in the
// enclosing scope: defaults and annotations, the return annotation, type
// parameters and base classes. A walrus or a sink there belongs to the
// enclosing function. Each header belongs to one definition, so every node
// is still scanned a bounded number of times.
func (x *pyExtraction) scanHeader(s *bodyScan, def *Node) {
	for _, c := range def.Children {
		switch c.Field {
		case "parameters", "return_type", "type_parameters", "superclasses":
			walk(c, func(n *Node) bool { return x.scanNode(s, n) })
		}
	}
}

// addAssign records `name = value` (also chained `a = b = value` and
// annotated `name: T = value`) as a candidate constant; any other target
// binds every name in it as dynamic.
func (x *pyExtraction) addAssign(s bodyScan, n *Node) {
	left, right := field(n, "left"), field(n, "right")
	for right != nil && right.Type == "assignment" {
		right = field(right, "right")
	}
	if left == nil || right == nil {
		return
	}
	if left.Type == "attribute" || left.Type == "subscript" {
		return // obj.a = v and d[k] = v bind no local name
	}
	if left.Type != "identifier" {
		x.bindAll(s, left)
		return
	}
	name := x.file.text(left)
	s.assigns[name] = append(s.assigns[name], right)
}

// bindAll marks every identifier under n as dynamic. Over-marking (an
// attribute base, a class name in a match pattern) only makes a sink
// dynamic, which is the safe direction.
func (x *pyExtraction) bindAll(s bodyScan, n *Node) {
	if n == nil {
		return
	}
	walk(n, func(c *Node) bool {
		if c.Type == "identifier" {
			s.dynamic[x.file.text(c)] = true
		}
		return true
	})
}

// constant reports whether n is built only from literals. It does not
// descend into calls, so the arguments of different sinks never share
// visited nodes. A list counts only when fresh, written in the sink call
// itself: a list bound to a name can be changed in place (q.append(user),
// q[0] = user, f(q)) between the assignment and the sink, so a name only
// holds immutable constants (strings, numbers, tuples of them).
func (x *pyExtraction) constant(n *Node, s bodyScan, fresh bool) bool {
	x.constBudget--
	if x.constBudget < 0 {
		return false
	}
	switch n.Type {
	case "string", "concatenated_string":
		_, ok := x.file.literalString(n)
		return ok
	case "integer", "float", "true", "false", "none":
		return true
	case "list", "tuple", "parenthesized_expression", "binary_operator":
		if n.Type == "list" && !fresh {
			return false
		}
		for _, c := range namedChildren(n) {
			if !x.constant(c, s, fresh) {
				return false
			}
		}
		return true
	case "identifier":
		return x.constantName(x.file.text(n), s)
	}
	return false
}

// constantName fails closed: a name is constant only when every binding of
// it in the function is a simple assignment of a constant, whatever the
// control flow (branches, try, loops) between them. A name with no local
// binding (module global, builtin) or one that reaches itself through a
// cycle is dynamic. The verdict is memoized per name, so each right-hand
// side is evaluated once per function and a chain such as
// z = "a" + ...; y = z + z; x = y + y costs linear time.
func (x *pyExtraction) constantName(name string, s bodyScan) bool {
	return s.constantName(name, x.file.nonlocals[name], &x.constBudget,
		func(r *Node) bool { return x.constant(r, s, false) })
}

// constantName is the memoized, language-neutral part of the verdict:
// rebound forces dynamic, and constant judges one right-hand side while
// spending *budget.
func (s bodyScan) constantName(name string, rebound bool, budget *int, constant func(*Node) bool) bool {
	if v, ok := s.names[name]; ok {
		return v == nameConst
	}
	rhs := s.assigns[name]
	if len(rhs) == 0 || s.dynamic[name] || rebound {
		s.names[name] = nameDynamic
		return false
	}
	s.names[name] = nameBusy
	v := nameConst
	for _, r := range rhs {
		if !constant(r) {
			v = nameDynamic
			break
		}
	}
	if *budget < 0 {
		delete(s.names, name) // the verdict is a budget guess, not a fact
		return false
	}
	s.names[name] = v
	return v == nameConst
}
