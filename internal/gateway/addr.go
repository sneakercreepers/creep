package gateway

import "net/netip"

// refusedPrefixes are ranges a DNS answer for a public model endpoint has no
// reason to contain. Returning one is how DNS rebinding and SSRF reach the
// local machine, the LAN or a cloud metadata service (169.254.169.254,
// fd00:ec2::254). Documentation, test and benchmarking ranges are never
// routed on the internet, so a public endpoint cannot live there either.
// Prefixes that embed an IPv4 address in a way we do not decode (6to4,
// Teredo, IPv4-compatible) are refused whole.
var refusedPrefixes = mustPrefixes(
	"0.0.0.0/8",        // "this network"; 0.0.0.0 reaches local listeners
	"10.0.0.0/8",       // private
	"100.64.0.0/10",    // carrier-grade NAT
	"127.0.0.0/8",      // loopback
	"169.254.0.0/16",   // link-local, cloud metadata
	"172.16.0.0/12",    // private
	"168.63.129.16/32", // Azure WireServer, the platform's metadata host
	"192.0.0.0/24",     // IETF protocol assignments
	"192.0.2.0/24",     // TEST-NET-1 documentation (RFC 5737)
	"192.168.0.0/16",   // private
	"198.18.0.0/15",    // benchmarking (RFC 2544)
	"198.51.100.0/24",  // TEST-NET-2 documentation (RFC 5737)
	"203.0.113.0/24",   // TEST-NET-3 documentation (RFC 5737)
	"224.0.0.0/3",      // multicast, reserved, broadcast
	"::/96",            // unspecified, loopback, IPv4-compatible
	"100::/64",         // discard
	"2001::/32",        // Teredo
	"2001:2::/48",      // benchmarking (RFC 5180)
	"2001:db8::/32",    // documentation (RFC 3849)
	"2002::/16",        // 6to4
	"3fff::/20",        // documentation (RFC 9637)
	"5f00::/16",        // SRv6 SIDs, never routed globally (RFC 9602)
	"64:ff9b:1::/48",   // local-use NAT64
	"fc00::/7",         // unique local
	"fe80::/10",        // link-local
	"ff00::/8",         // multicast
	"fec0::/10",        // deprecated site-local
)

// embedsIPv4 are /96 prefixes whose last 32 bits are a whole IPv4 address
// that a translator will reach; the address is judged by that IPv4.
var embedsIPv4 = mustPrefixes(
	"64:ff9b::/96",    // well-known NAT64 (RFC 6052)
	"::ffff:0:0:0/96", // SIIT IPv4-translated (RFC 7915); IPv4-mapped is unmapped first
)

func mustPrefixes(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}

// publicAddr reports whether a DNS answer address may be dialed. An ISATAP
// address must pass both as IPv6 and as the IPv4 its interface ID embeds.
func publicAddr(ip netip.Addr) bool {
	ip = ip.Unmap()
	if v4, ok := isatapIPv4(ip); ok && !publicAddr(v4) {
		return false
	}
	ip = embeddedIPv4(ip)
	if !ip.IsValid() || ip.Zone() != "" {
		return false
	}
	for _, p := range refusedPrefixes {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}

// embeddedIPv4 returns the IPv4 address inside an embedsIPv4 prefix, or ip.
func embeddedIPv4(ip netip.Addr) netip.Addr {
	for _, p := range embedsIPv4 {
		if p.Contains(ip) {
			return lastIPv4(ip)
		}
	}
	return ip
}

// isatapIPv4 returns the IPv4 address in an ISATAP interface ID
// (RFC 5214: [00|02]00:5efe:w.x.y.z, the low bits of the first byte being
// the universal/local and group flags). An ISATAP router forwards to that
// IPv4 address, whatever the /64 in front of it.
func isatapIPv4(ip netip.Addr) (netip.Addr, bool) {
	if !ip.Is6() {
		return netip.Addr{}, false
	}
	b := ip.As16()
	if b[8]&^0x03 != 0 || b[9] != 0 || b[10] != 0x5e || b[11] != 0xfe {
		return netip.Addr{}, false
	}
	return lastIPv4(ip), true
}

func lastIPv4(ip netip.Addr) netip.Addr {
	b := ip.As16()
	return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
}
