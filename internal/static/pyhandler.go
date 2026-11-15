package static

import "strings"

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
			dynamic:       first != nil && !x.constant(first, s),
			parameterized: api.Kind() == SinkSQL && (len(pos) > 1 || hasKeyword(x.file, kw, "parameters", "params")),
			partial:       x.constBudget < 0,
		})
	}
	return out
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
