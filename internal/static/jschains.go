package static

// maxMountPaths caps the mounts kept per router and the mount chains a route
// expands to. Past it the route is marked partial: a dropped chain might be
// a public mount.
const maxMountPaths = 16

// mountHop is one step up a mount chain: the mount of a router on its parent.
type mountHop struct{ m *jsMount }

// mountChain is one way a router is reached from a root app, innermost hop
// first. cut is set when the chain ran past maxMountDepth or into a cycle,
// so the full path is unknown and nothing beyond it claims auth.
type mountChain struct {
	hops []mountHop
	cut  bool
}

// chainsOf lists the mount chains of r, memoized per receiver. A router
// mounted twice yields two chains, so each mount keeps its own path and
// auth. partial is set when chains were dropped at the cap.
func (x *jsExtraction) chainsOf(r *jsReceiver, depth int) (chains []mountChain, partial bool) {
	switch {
	case r == nil || len(r.mounts) == 0:
		return []mountChain{{}}, false
	case r.chainsDone:
		return r.chains, r.chainsPartial
	case depth >= maxMountDepth || r.busy:
		return []mountChain{{cut: true}}, false
	}
	r.busy = true
	partial = r.mountOverflow
	for i := range r.mounts {
		parents, p := x.chainsOf(r.mounts[i].parent, depth+1)
		partial = partial || p
		for _, pc := range parents {
			if len(chains) == maxMountPaths {
				partial = true
				break
			}
			chains = append(chains, prependHop(mountHop{&r.mounts[i]}, pc))
		}
	}
	r.busy = false
	r.chains, r.chainsPartial, r.chainsDone = chains, partial, true
	return chains, partial
}

// prependHop adds h in front of c, cutting the chain at maxMountDepth hops.
func prependHop(h mountHop, c mountChain) mountChain {
	hops := append([]mountHop{h}, c.hops...)
	if len(hops) > maxMountDepth {
		return mountChain{hops: hops[:maxMountDepth], cut: true}
	}
	return mountChain{hops: hops, cut: c.cut}
}

// chainPrefix composes the mount paths of a chain, outermost first.
func chainPrefix(c mountChain) mountPrefix {
	p := mountPrefix{dynamic: c.cut}
	for _, h := range c.hops {
		p.path = joinPath(h.m.at.path, p.path)
		p.dynamic = p.dynamic || h.m.at.dynamic
	}
	return p
}

// chainAuth reports whether auth middleware guards a route declared at pos
// on r with the given router-local path, reached through c: used before it
// on r, set on a mount of the chain, or used on a parent before that mount.
// An ambiguous receiver anywhere on the chain claims nothing.
func chainAuth(r *jsReceiver, c mountChain, path string, known bool, pos uint32) bool {
	if r == nil || r.ambiguous {
		return false
	}
	for _, h := range c.hops {
		if h.m.parent.ambiguous {
			return false
		}
	}
	cur := r
	for i := 0; ; i++ {
		if cur.covers(path, known && len(path) < maxPathBytes, pos) {
			return true
		}
		if i == len(c.hops) {
			return false
		}
		m := c.hops[i].m
		if m.at.auth {
			return true
		}
		path, known = joinPath(m.at.path, path), known && !m.at.dynamic
		cur, pos = m.parent, m.pos
	}
}
