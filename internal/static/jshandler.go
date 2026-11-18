package static

// jsFacts summarizes a handler once per definition: the sinks in it (nested
// callbacks included), then those of same-file top-level helpers it calls,
// and whether it calls an auth-named function. A cut scan marks it partial.
func (x *jsExtraction) facts(def *Node) handlerFacts {
	if h, ok := x.handlers[def]; ok {
		return h
	}
	var h handlerFacts
	h.add(x.helperSinks(def), false)
	h.partial = h.partial || x.scan(def).cut || x.scan(def).foreign
	seen := map[*Node]bool{def: true}
	for _, call := range x.scan(def).calls {
		name, method := x.file.resolve(field(call, "function"))
		if name == "" {
			continue
		}
		h.authCall = h.authCall || jsAuthCall(name, method)
		helper := x.file.funcs[name]
		if method || helper == nil || seen[helper] {
			continue
		}
		seen[helper] = true
		h.add(x.helperSinks(helper), true)
		h.partial = h.partial || x.scan(helper).cut || x.scan(helper).foreign
	}
	x.handlers[def] = h
	return h
}

// jsAuthCall is authName without the CommonJS require and the validation
// idiom .required(), which share its "require" word.
func jsAuthCall(name string, method bool) bool {
	if name == "require" || (method && name == "required") {
		return false
	}
	return authName(name)
}

// helperSinks lists the sinks called anywhere in a function.
func (x *jsExtraction) helperSinks(def *Node) []foundSink {
	if s, ok := x.helpers[def]; ok {
		return s
	}
	s := x.directSinks(x.scan(def))
	x.helpers[def] = s
	return s
}

// directSinks lists the sink calls of a scan. A call the scan cannot
// classify (into a module of the repository that matches no sink, a
// sink-named method on an unresolved import alias, a ".find" whose argument
// may or may not be a filter) sets s.foreign and the route becomes partial.
func (x *jsExtraction) directSinks(s *jsScan) []foundSink {
	var out []foundSink
	for _, call := range s.calls {
		args := jsArgs(call)
		if args == nil {
			continue // tagged template: the tag gets the parts, not a string
		}
		api, ok, unseen := x.sinkCall(field(call, "function"), args, s)
		s.foreign = s.foreign || unseen
		if !ok {
			continue
		}
		out = append(out, foundSink{
			api:           api,
			line:          line(call),
			dynamic:       s.cut || (len(args) > 0 && !x.constant(args[0], s, true)),
			parameterized: api.Kind() == SinkSQL && len(args) > 1 && !isFunction(args[1]),
			partial:       x.constBudget < 0 || s.cut,
		})
	}
	return out
}

// sinkCall classifies one call: a sink, or not one, and unseen when the
// scan cannot tell, so the route must be partial.
func (x *jsExtraction) sinkCall(callee *Node, args []*Node, s *jsScan) (api SinkAPI, ok, unseen bool) {
	api, ok, local := x.classify(callee)
	if !ok {
		return 0, false, local || x.file.unseenAliasCall(callee)
	}
	if api.String() != jsFindNeedsObject {
		return api, true, false
	}
	switch x.findKind(callee, args, s, local) {
	case findFilter:
		return api, true, false
	case findUnknown:
		return 0, false, true
	}
	return 0, false, local
}

// classify matches a callee against the sink table by its resolved name,
// then, for a receiver from a module of the repository (a model, a db
// client in ./db), by its method name, as for any other variable. local is
// set for such a callee.
func (x *jsExtraction) classify(callee *Node) (api SinkAPI, ok, local bool) {
	name, method := x.file.resolve(callee)
	if api, ok = lookupJSSink(name, method); ok {
		return api, true, false
	}
	m, local := x.file.localCall(callee)
	if !local || m == "" {
		return 0, false, local
	}
	api, ok = lookupJSSink(m, true)
	return api, ok, true
}

// jsArgs returns a call's arguments, or nil for a tagged template. A call
// with no arguments returns an empty, non-nil slice.
func jsArgs(call *Node) []*Node {
	args := field(call, "arguments")
	if args == nil || args.Type != "arguments" {
		return nil
	}
	return append([]*Node{}, namedChildren(args)...)
}
