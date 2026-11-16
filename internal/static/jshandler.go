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
	h.partial = h.partial || x.scan(def).cut
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
		h.partial = h.partial || x.scan(helper).cut
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

func (x *jsExtraction) directSinks(s *jsScan) []foundSink {
	var out []foundSink
	for _, call := range s.calls {
		args := jsArgs(call)
		if args == nil {
			continue // tagged template: the tag gets the parts, not a string
		}
		name, method := x.file.resolve(field(call, "function"))
		api, ok := lookupJSSink(name, method)
		if !ok || (api.String() == jsFindNeedsObject && (len(args) == 0 || args[0].Type != "object")) {
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

// jsArgs returns a call's arguments, or nil for a tagged template. A call
// with no arguments returns an empty, non-nil slice.
func jsArgs(call *Node) []*Node {
	args := field(call, "arguments")
	if args == nil || args.Type != "arguments" {
		return nil
	}
	return append([]*Node{}, namedChildren(args)...)
}
