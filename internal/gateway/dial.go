package gateway

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"
)

// ErrPrivateAddress means a DNS answer pointed an allowlisted name at a
// loopback, private, link-local or otherwise non-public address.
var ErrPrivateAddress = errors.New("resolved to a non-public address not listed in egress.allow")

// maxPinnedAddrs caps the addresses kept from one DNS answer, so whoever
// controls DNS for an allowlisted name cannot make one dial try dozens of
// black-holed addresses.
const maxPinnedAddrs = 8

// Resolver is the subset of *net.Resolver the gateway uses. Tests inject one
// to count lookups and to change answers between calls.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// DialFunc opens a TCP connection to an IP:port address.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// localhostAddrs is what "localhost" means; the name is never resolved, so a
// hosts file or resolver cannot point it elsewhere.
var localhostAddrs = []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::1")}

// pinningDialer resolves each allowlisted host once and dials only the pinned
// addresses, so a later DNS answer (rebinding) cannot move the connection
// while the pinned addresses work. When every pinned address fails, the pin
// is dropped and the next dial resolves again; that answer passes the same
// public-address check. TLS still runs over the hostname: the transport sets
// SNI and verifies the certificate against the URL host.
type pinningDialer struct {
	allow    allowlist
	resolver Resolver
	dial     DialFunc
	limits   timeLimits

	mu     sync.Mutex // guards pinned, never held during a lookup
	pinned map[string]*pin
}

func newPinningDialer(allow allowlist, res Resolver, dial DialFunc, limits timeLimits) *pinningDialer {
	if res == nil {
		res = net.DefaultResolver
	}
	if dial == nil {
		dial = (&net.Dialer{Timeout: dialTimeout}).DialContext
	}
	return &pinningDialer{allow: allow, resolver: res, dial: dial, limits: limits.withDefaults(), pinned: map[string]*pin{}}
}

func (d *pinningDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	h, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("dial %q: %w", addr, err)
	}
	host, err := normalizeHost(h)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}
	if !d.allow.permitsDial(host, port) {
		return nil, fmt.Errorf("dial %q: %w", addr, ErrNotAllowed)
	}
	p, err := d.pin(ctx, host)
	if err != nil {
		return nil, err
	}
	conn, err := d.dialFirst(ctx, network, p.addrs, port)
	if err != nil && ctx.Err() == nil {
		// Every pinned address failed on the network or the gateway's own
		// deadline, not the caller's: the provider may have moved.
		d.unpin(host, p)
	}
	return conn, err
}

// dialFirst tries the pinned addresses in order under one deadline for all
// of them.
func (d *pinningDialer) dialFirst(ctx context.Context, network string, addrs []netip.Addr, port string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, d.limits.dialAll)
	defer cancel()
	var errs []error
	for _, ip := range addrs {
		if err := ctx.Err(); err != nil {
			errs = append(errs, err)
			break
		}
		conn, err := d.dial(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
		errs = append(errs, err)
	}
	return nil, fmt.Errorf("dial pinned addresses: %w", errors.Join(errs...))
}

func (d *pinningDialer) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	if host == "localhost" {
		return localhostAddrs, nil
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{ip}, nil
	}
	ctx, cancel := context.WithTimeout(ctx, d.limits.lookup)
	defer cancel()
	found, err := d.resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("resolve %q: %w", host, err)
	}
	return d.checkResolved(host, found)
}

// checkResolved refuses the whole answer if any address is non-public: a
// mixed answer is itself a rebinding signal. There is no exemption here; a
// model on a private address is reached by allowlisting and requesting that
// IP literal, which resolve returns without a lookup. Every address is
// checked before the answer is cut to maxPinnedAddrs.
func (d *pinningDialer) checkResolved(host string, found []netip.Addr) ([]netip.Addr, error) {
	if len(found) == 0 {
		return nil, fmt.Errorf("resolve %q: no addresses", host)
	}
	addrs := make([]netip.Addr, 0, len(found))
	for _, ip := range found {
		ip = ip.Unmap().WithZone("")
		if !publicAddr(ip) {
			return nil, fmt.Errorf("resolve %q: %s: %w", host, ip, ErrPrivateAddress)
		}
		addrs = append(addrs, ip)
	}
	return addrs[:min(len(addrs), maxPinnedAddrs)], nil
}

// timeLimits are the gateway's own time bounds. Zero fields take the
// defaults; tests set short ones.
type timeLimits struct {
	lookup    time.Duration // one DNS lookup
	dialAll   time.Duration // one dial over every pinned address
	bodyIdle  time.Duration // a response body read with no new bytes
	bodyTotal time.Duration // a whole response body after the headers
}

func (l timeLimits) withDefaults() timeLimits {
	return timeLimits{
		lookup:    orDefault(l.lookup, dialTimeout),
		dialAll:   orDefault(l.dialAll, dialAllTimeout),
		bodyIdle:  orDefault(l.bodyIdle, bodyIdleTimeout),
		bodyTotal: orDefault(l.bodyTotal, bodyTotalTimeout),
	}
}

func orDefault(v, def time.Duration) time.Duration {
	if v <= 0 {
		return def
	}
	return v
}
