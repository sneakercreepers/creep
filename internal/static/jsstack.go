package static

// maxStackEntries caps the middleware and handler entries analyzed per
// route; past it the route is marked partial.
const maxStackEntries = 64

// handlerIndex picks the handler: the last entry that is not auth
// middleware, or the last entry when all are. Auth placed after the
// handler does not guard it, since the handler may answer first.
func (x *jsExtraction) handlerIndex(stack []*Node) int {
	for i := len(stack) - 1; i >= 0; i-- {
		if !x.authMiddleware(stack[i]) {
			return i
		}
	}
	return len(stack) - 1
}

// addHandler sets the route's handler name and line from stack[hi], and its
// facts from every entry of the stack.
func (x *jsExtraction) addHandler(r *foundRoute, stack []*Node, hi int, call *Node) {
	def, name := x.handlerDef(stack[hi])
	r.handler, r.line = capText(name, maxHandlerBytes), line(call)
	if def != nil {
		r.line = line(def)
	}
	r.facts = x.stackFacts(stack, hi)
	if r.facts.authCall {
		r.auth |= AuthCall
	}
}

// stackFacts merges the facts of every function the route runs: inline
// middleware, same-file middleware, wrapper functions and the handler. An
// entry that is neither a function of the file nor recognized auth
// middleware (an imported controller, a library factory such as
// upload.single()) is code the scan cannot see, so the route is partial.
// Auth calls count only up to the handler.
func (x *jsExtraction) stackFacts(stack []*Node, hi int) handlerFacts {
	var h handlerFacts
	if len(stack) > maxStackEntries {
		stack, h.partial = stack[:maxStackEntries], true
	}
	sinkSeen, defSeen := map[foundSink]bool{}, map[*Node]bool{}
	for i, entry := range stack {
		defs, ok := x.entryDefs(entry)
		if !ok && !x.authMiddleware(entry) {
			h.partial = true
		}
		for _, d := range defs {
			if !defSeen[d] {
				defSeen[d] = true
				h.merge(x.facts(d), i <= hi, sinkSeen)
			}
		}
	}
	return h
}

// merge adds f to h, dropping sinks already listed (a helper shared by two
// middlewares) and stopping at maxRouteSinks.
func (h *handlerFacts) merge(f handlerFacts, countAuth bool, seen map[foundSink]bool) {
	h.authCall = h.authCall || (countAuth && f.authCall)
	h.partial = h.partial || f.partial
	h.truncated = h.truncated || f.truncated
	for _, s := range f.sinks {
		if seen[s] {
			continue
		}
		if len(h.sinks) == maxRouteSinks {
			h.truncated = true
			return
		}
		seen[s] = true
		h.sinks = append(h.sinks, s)
	}
}

// entryDefs resolves one stack entry to the functions of the file that run
// for it: a function literal, a top-level function, a same-file factory or
// wrapper such as asyncHandler(fn), and the function it wraps. ok is false
// when part of the entry is code outside the file.
func (x *jsExtraction) entryDefs(n *Node) (defs []*Node, ok bool) {
	ok = true
	for range maxHandlerWraps {
		n = unwrapCast(n)
		switch {
		case n == nil:
			return defs, false
		case isFunction(n):
			return append(defs, n), ok
		case n.Type == "identifier" && x.file.funcs[x.file.text(n)] != nil:
			return append(defs, x.file.funcs[x.file.text(n)]), ok
		case n.Type != "call_expression":
			return defs, false
		}
		if callee := x.calleeFunc(n); callee != nil {
			defs = append(defs, callee)
		} else {
			ok = false // an imported or unknown wrapper or factory
		}
		args := jsArgs(n)
		if len(args) == 0 || !x.callable(args[len(args)-1]) {
			return defs, ok
		}
		n = args[len(args)-1]
	}
	return defs, false
}

// calleeFunc is the same-file function a call invokes, or nil.
func (x *jsExtraction) calleeFunc(call *Node) *Node {
	fn := unwrapCast(field(call, "function"))
	if fn == nil || fn.Type != "identifier" {
		return nil
	}
	return x.file.funcs[x.file.text(fn)]
}

// callable reports whether an argument is a function, a function name of
// the file, or a call that may return one.
func (x *jsExtraction) callable(n *Node) bool {
	n = unwrapCast(n)
	switch {
	case n == nil:
		return false
	case isFunction(n), n.Type == "call_expression":
		return true
	case n.Type == "identifier":
		return x.file.funcs[x.file.text(n)] != nil
	}
	return false
}

// handlerDef resolves a handler expression to the function that answers:
// a function literal, a top-level function name, or either wrapped in calls
// such as asyncHandler(fn). name is "" for an anonymous function.
func (x *jsExtraction) handlerDef(n *Node) (def *Node, name string) {
	for range maxHandlerWraps {
		n = unwrapCast(n)
		switch {
		case n == nil:
			return nil, ""
		case isFunction(n):
			return n, x.file.text(field(n, "name"))
		case n.Type == "identifier":
			return x.file.funcs[x.file.text(n)], x.file.text(n)
		case n.Type == "call_expression":
			args := jsArgs(n)
			if len(args) == 0 {
				return nil, ""
			}
			n = args[len(args)-1]
		default:
			return nil, x.file.text(n)
		}
	}
	return nil, ""
}
