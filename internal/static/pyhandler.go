package static

import (
	"sort"
	"strings"
)

// foundSink is a sink call before it gets an ID.
type foundSink struct {
	api                         SinkAPI
	line                        int
	dynamic, parameterized, ind bool
	// partial is set when the constant-argument budget ran out, so dynamic
	// is a conservative guess.
	partial bool
}

// handlerFacts is what a function body shows: its sinks (direct, then those
// of same-file helpers it calls) and whether it calls an auth-named function.
type handlerFacts struct {
	sinks     []foundSink
	authCall  bool
	truncated bool // more than maxRouteSinks sinks
	partial   bool // a sink's analysis ran out of budget
}

// bodyScan is one pass over a function body.
type bodyScan struct {
	calls   []*Node
	assigns map[string][]*Node // name -> right-hand sides in source order
}

// maxRouteSinks caps the sinks kept per handler.
const maxRouteSinks = 256

// maxConstVisits caps the nodes DynamicArg analysis visits per file. With
// memoized assignments real files need far fewer; past the cap every sink is
// treated as dynamic and its route marked partial (fails closed).
const maxConstVisits = 1 << 16

// authWords mark a function, decorator or dependency as an auth check.
var authWords = []string{"auth", "login", "jwt", "token", "permission", "admin", "require", "current_user", "role", "oauth", "api_key", "apikey", "credential", "signed_in", "logged_in", "protected"}

// authName reports whether the last segment of a dotted name looks like an
// auth check.
func authName(name string) bool {
	last := strings.ToLower(name[strings.LastIndexByte(name, '.')+1:])
	for _, w := range authWords {
		if strings.Contains(last, w) {
			return true
		}
	}
	return false
}

// facts summarizes a handler once per definition. Each helper counts once and
// the sink list stops at maxRouteSinks, so a hostile handler cannot blow up.
func (x *pyExtraction) facts(def *Node) handlerFacts {
	if h, ok := x.handlers[def]; ok {
		return h
	}
	var h handlerFacts
	h.add(x.helperSinks(def), false)
	seen := map[*Node]bool{def: true}
	for _, call := range x.scan(def).calls {
		name, method := x.file.resolve(field(call, "function"))
		if name == "" {
			continue
		}
		h.authCall = h.authCall || authName(name)
		helper := x.file.funcs[name]
		if method || helper == nil || seen[helper] {
			continue
		}
		seen[helper] = true
		h.add(x.helperSinks(helper), true)
	}
	x.handlers[def] = h
	return h
}

func (h *handlerFacts) add(sinks []foundSink, indirect bool) {
	for _, s := range sinks {
		if len(h.sinks) == maxRouteSinks {
			h.truncated = true
			return
		}
		s.ind = indirect
		h.partial = h.partial || s.partial
		h.sinks = append(h.sinks, s)
	}
}

// helperSinks lists the sinks called directly in a function's body.
func (x *pyExtraction) helperSinks(def *Node) []foundSink {
	if s, ok := x.helpers[def]; ok {
		return s
	}
	s := x.directSinks(x.scan(def))
	x.helpers[def] = s
	return s
}

// scan collects calls and simple assignments in a body once, skipping nested
// function and class bodies so no node is scanned for two handlers.
func (x *pyExtraction) scan(def *Node) bodyScan {
	if s, ok := x.scans[def]; ok {
		return s
	}
	s := bodyScan{assigns: map[string][]*Node{}}
	body := field(def, "body")
	if body == nil {
		x.scans[def] = s
		return s
	}
	walk(body, func(n *Node) bool {
		switch n.Type {
		case "function_definition", "class_definition", "decorated_definition":
			return false
		case "call":
			s.calls = append(s.calls, n)
		case "assignment", "augmented_assignment":
			x.addAssign(s, n)
		}
		return true
	})
	x.scans[def] = s
	return s
}

func (x *pyExtraction) addAssign(s bodyScan, n *Node) {
	left, right := field(n, "left"), field(n, "right")
	if left == nil || right == nil || left.Type != "identifier" {
		return
	}
	if n.Type == "augmented_assignment" {
		right = n // `q += x` is never treated as constant
	}
	name := x.file.text(left)
	s.assigns[name] = append(s.assigns[name], right)
}

func (x *pyExtraction) directSinks(s bodyScan) []foundSink {
	var out []foundSink
	for _, call := range s.calls {
		name, method := x.file.resolve(field(call, "function"))
		api, ok := lookupSink(name, method)
		if !ok {
			continue
		}
		pos, kw := callArgs(call)
		first := firstArg(pos, kw)
		out = append(out, foundSink{
			api:           api,
			line:          line(call),
			dynamic:       first != nil && !x.constant(first, s, first.StartByte),
			parameterized: api.Kind() == SinkSQL && (len(pos) > 1 || hasKeyword(x.file, kw, "parameters", "params")),
			partial:       x.constBudget < 0,
		})
	}
	return out
}

// constant reports whether n is built only from literals, following local
// assignments made before offset `before`. It does not descend into calls,
// so the arguments of different sinks never share visited nodes.
func (x *pyExtraction) constant(n *Node, s bodyScan, before uint32) bool {
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
		for _, c := range namedChildren(n) {
			if !x.constant(c, s, before) {
				return false
			}
		}
		return true
	case "identifier":
		rhs := lastAssignBefore(s.assigns[x.file.text(n)], before)
		return rhs != nil && x.constantAssign(rhs, s)
	}
	return false
}

// constantAssign memoizes constant per right-hand side, so a chain such as
// z = "a" + ...; y = z + z; x = y + y is evaluated once per assignment
// instead of once per path through the chain. An identifier only resolves to
// an assignment that starts earlier, so the recursion cannot cycle.
func (x *pyExtraction) constantAssign(rhs *Node, s bodyScan) bool {
	if v, ok := x.constMemo[rhs]; ok {
		return v
	}
	v := x.constant(rhs, s, rhs.StartByte)
	if x.constBudget >= 0 {
		x.constMemo[rhs] = v
	}
	return v
}

// lastAssignBefore picks the last right-hand side starting before offset;
// binary search keeps many assignments to one name from going quadratic.
func lastAssignBefore(rhs []*Node, before uint32) *Node {
	i := sort.Search(len(rhs), func(i int) bool { return rhs[i].StartByte >= before })
	if i == 0 {
		return nil
	}
	return rhs[i-1]
}

// callArgs splits a call's arguments into positional and keyword nodes.
func callArgs(call *Node) (pos, kw []*Node) {
	args := field(call, "arguments")
	if args == nil {
		return nil, nil
	}
	for _, c := range namedChildren(args) {
		if c.Type == "keyword_argument" {
			kw = append(kw, c)
		} else {
			pos = append(pos, c)
		}
	}
	return pos, kw
}

// firstArg is the first positional argument, else the first keyword value.
func firstArg(pos, kw []*Node) *Node {
	if len(pos) > 0 {
		return pos[0]
	}
	if len(kw) > 0 {
		return field(kw[0], "value")
	}
	return nil
}

// keyword returns the value of the first keyword argument with one of names.
func keyword(f *pyFile, kw []*Node, names ...string) *Node {
	for _, k := range kw {
		name := f.text(field(k, "name"))
		for _, want := range names {
			if name == want {
				return field(k, "value")
			}
		}
	}
	return nil
}

func hasKeyword(f *pyFile, kw []*Node, names ...string) bool {
	return keyword(f, kw, names...) != nil
}

func line(n *Node) int { return int(n.Start.Row) + 1 }
