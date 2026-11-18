package static

import "strings"

// maxScanVisits caps the nodes all JavaScript handler and helper scans visit
// per file. A scan covers nested functions, so handlers nested in handlers
// would otherwise cost quadratic time; past the cap a scan is cut, its
// sinks count as dynamic and its routes are marked partial.
const maxScanVisits = 1 << 22

// jsScan is one pass over a JavaScript function, nested functions included:
// callbacks run as part of the handler, and a closure can rebind the
// handler's variables, so every binding anywhere inside counts.
type jsScan struct {
	bodyScan
	// opaque is set by `with`, a direct eval or a cut scan: any name may
	// have been rebound, so none is constant.
	opaque bool
	// cut is set when the scan ran out of budget.
	cut bool
	// foreign is set when the function makes a call the scan cannot
	// classify, such as into a module of the repository (jshandler.go).
	foreign bool
}

func (x *jsExtraction) scan(fn *Node) *jsScan {
	if s, ok := x.scans[fn]; ok {
		return s
	}
	s := &jsScan{bodyScan: bodyScan{assigns: map[string][]*Node{}, dynamic: map[string]bool{}, names: map[string]nameState{}}}
	walk(fn, func(n *Node) bool {
		x.scanBudget--
		if x.scanBudget < 0 {
			s.cut, s.opaque = true, true
			return false
		}
		x.scanNode(s, n)
		return true
	})
	x.scans[fn] = s
	return s
}

// scanNode records what one node binds.
func (x *jsExtraction) scanNode(s *jsScan, n *Node) {
	switch n.Type {
	case "call_expression":
		s.calls = append(s.calls, n)
		s.opaque = s.opaque || x.file.text(field(n, "function")) == "eval"
	case "with_statement":
		s.opaque = true
	case "variable_declarator":
		x.addDeclarator(s, n)
	case "assignment_expression":
		x.addAssign(s, n)
	case "augmented_assignment_expression", "for_in_statement":
		x.bindAll(s, field(n, "left"))
	case "update_expression":
		x.bindAll(s, field(n, "argument"))
	case "catch_clause":
		x.bindAll(s, field(n, "parameter"))
	case "formal_parameters":
		x.bindAll(s, n)
	case "arrow_function":
		x.bindAll(s, field(n, "parameter"))
	}
	if strings.HasSuffix(n.Type, "_declaration") || isFunction(n) || n.Type == "class" {
		x.bindAll(s, field(n, "name"))
	}
}

// addDeclarator records `const|let|var name = value` as a candidate
// constant. A declarator without a value or with a pattern binds dynamically.
func (x *jsExtraction) addDeclarator(s *jsScan, n *Node) {
	name, value := field(n, "name"), field(n, "value")
	if name == nil || name.Type != "identifier" || value == nil {
		x.bindAll(s, name)
		return
	}
	s.assigns[x.file.text(name)] = append(s.assigns[x.file.text(name)], value)
}

// addAssign records `name = value` (also chained `a = b = value`); member
// and subscript targets bind no local name; patterns bind dynamically.
func (x *jsExtraction) addAssign(s *jsScan, n *Node) {
	left, right := field(n, "left"), field(n, "right")
	for right != nil && right.Type == "assignment_expression" {
		right = field(right, "right")
	}
	switch {
	case left == nil || right == nil:
	case left.Type == "member_expression" || left.Type == "subscript_expression":
	case left.Type == "identifier":
		s.assigns[x.file.text(left)] = append(s.assigns[x.file.text(left)], right)
	default:
		x.bindAll(s, left)
	}
}

// bindAll marks every identifier under n as dynamic, including shorthand
// pattern names. Over-marking only makes a sink dynamic, the safe direction.
func (x *jsExtraction) bindAll(s *jsScan, n *Node) {
	if n == nil {
		return
	}
	walk(n, func(c *Node) bool {
		if c.Type == "identifier" || c.Type == "shorthand_property_identifier_pattern" {
			s.dynamic[x.file.text(c)] = true
		}
		return true
	})
}

// constant reports whether n is built only from literals, like the Python
// rule: a name holds only primitives (strings, template literals without
// substitutions, numbers, booleans, null), and an array or object literal
// counts only when fresh, written in the sink call itself, since a bound one
// can be changed in place before the sink. It does not descend into calls.
func (x *jsExtraction) constant(n *Node, s *jsScan, fresh bool) bool {
	x.constBudget--
	if x.constBudget < 0 {
		return false
	}
	switch n.Type {
	case "string", "template_string":
		_, ok := x.file.literalString(n)
		return ok
	case "number", "true", "false", "null", "undefined":
		return true
	case "parenthesized_expression", "binary_expression":
		return x.allConstant(namedChildren(n), s, fresh)
	case "array":
		return fresh && x.allConstant(namedChildren(n), s, fresh)
	case "object":
		return fresh && x.objectConstant(n, s)
	case "identifier":
		return x.constantName(x.file.text(n), s)
	case "as_expression", "satisfies_expression", "non_null_expression", "type_assertion":
		// A TypeScript cast does not change the value.
		if inner := unwrapCast(n); inner != n {
			return x.constant(inner, s, fresh)
		}
	}
	return false
}

func (x *jsExtraction) allConstant(nodes []*Node, s *jsScan, fresh bool) bool {
	for _, c := range nodes {
		if !x.constant(c, s, fresh) {
			return false
		}
	}
	return true
}

// objectConstant: every key is a plain name or literal and every value is
// constant; computed keys, spreads and methods are dynamic.
func (x *jsExtraction) objectConstant(n *Node, s *jsScan) bool {
	for _, c := range namedChildren(n) {
		switch c.Type {
		case "pair":
			key := field(c, "key")
			if key == nil || key.Type == "computed_property_name" {
				return false
			}
			if v := field(c, "value"); v == nil || !x.constant(v, s, true) {
				return false
			}
		case "shorthand_property_identifier":
			if !x.constantName(x.file.text(c), s) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// constantName fails closed exactly as the Python rule does (see
// bodyScan.constantName); an opaque scan makes every name dynamic.
func (x *jsExtraction) constantName(name string, s *jsScan) bool {
	return s.constantName(name, s.opaque, &x.constBudget,
		func(r *Node) bool { return x.constant(r, s, false) })
}
