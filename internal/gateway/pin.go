package gateway

import (
	"context"
	"fmt"
	"net/netip"
)

// pin holds one host's addresses. The first dial of a host resolves it;
// dials that arrive meanwhile wait on ready or on their own context, so a
// slow lookup stalls only dials to the same host and never past a caller's
// deadline.
type pin struct {
	ready chan struct{} // closed when the lookup ends
	addrs []netip.Addr  // written before ready is closed
	err   error         // written before ready is closed
}

// pin returns the pin of host, resolving when none is held. A failed lookup
// is not cached: it may have failed on the resolving dial's own context, so
// a waiter tries again. The map stays small: DialContext pins only
// allowlisted hosts.
func (d *pinningDialer) pin(ctx context.Context, host string) (*pin, error) {
	for {
		p, owner := d.claim(host)
		if owner {
			return d.fill(ctx, host, p)
		}
		select {
		case <-p.ready:
		case <-ctx.Done():
			return nil, fmt.Errorf("resolve %q: %w", host, ctx.Err())
		}
		if p.err == nil {
			return p, nil
		}
	}
}

// claim returns host's pin, or a new empty one that the caller must fill.
func (d *pinningDialer) claim(host string) (*pin, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if p, ok := d.pinned[host]; ok {
		return p, false
	}
	p := &pin{ready: make(chan struct{})}
	d.pinned[host] = p
	return p, true
}

// fill resolves host into p and wakes its waiters. A failed pin is removed
// before the waiters wake, so their retry starts a new lookup.
func (d *pinningDialer) fill(ctx context.Context, host string, p *pin) (*pin, error) {
	p.addrs, p.err = d.resolve(ctx, host)
	if p.err != nil {
		d.unpin(host, p)
	}
	close(p.ready)
	if p.err != nil {
		return nil, p.err
	}
	return p, nil
}

// unpin drops p if it is still host's pin, so the next dial resolves again.
// A newer pin another dial already made is kept.
func (d *pinningDialer) unpin(host string, p *pin) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.pinned[host] == p {
		delete(d.pinned, host)
	}
}
