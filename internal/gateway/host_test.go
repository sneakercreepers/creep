package gateway

import (
	"errors"
	"net/netip"
	"testing"
)

func TestNormalizeHost(t *testing.T) {
	tests := []struct {
		in, want string
		wantErr  bool
	}{
		{in: "API.Example.COM.", want: "api.example.com"},
		{in: "localhost", want: "localhost"},
		{in: "::ffff:127.0.0.1", want: "127.0.0.1"},
		{in: "::1", want: "::1"},
		{in: "xn--bcher-kva.example", want: "xn--bcher-kva.example"},
		{in: "", wantErr: true},
		{in: "2130706433", wantErr: true},        // decimal 127.0.0.1
		{in: "0x7f000001", wantErr: true},        // hex
		{in: "0x7f.0.0.1", wantErr: true},        // hex octet
		{in: "0177.0.0.1", wantErr: true},        // octal
		{in: "127.1", wantErr: true},             // short form
		{in: "127.0.0.1.", want: "127.0.0.1"},    // trailing dot on a literal
		{in: "fe80::1%eth0", wantErr: true},      // zone
		{in: "local_host", wantErr: true},        // underscore
		{in: "-evil.example", wantErr: true},     // leading hyphen
		{in: "evil..example", wantErr: true},     // empty label
		{in: "evil.example/x", wantErr: true},    // path character
		{in: "bücher.example", wantErr: true},    // raw unicode, want punycode
		{in: "a.b.c.d.e.f.g.123", wantErr: true}, // numeric last label
	}
	for _, tt := range tests {
		got, err := normalizeHost(tt.in)
		if (err != nil) != tt.wantErr {
			t.Errorf("normalizeHost(%q) err = %v, wantErr %v", tt.in, err, tt.wantErr)
			continue
		}
		if err != nil && !errors.Is(err, ErrInvalidHost) {
			t.Errorf("normalizeHost(%q) err = %v, want ErrInvalidHost", tt.in, err)
		}
		if got != tt.want {
			t.Errorf("normalizeHost(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestIsLoopbackHost(t *testing.T) {
	tests := []struct {
		host string
		want bool
	}{
		{"localhost", true},
		{"127.0.0.1", true},
		{"127.255.10.9", true},
		{"::1", true},
		{"localhost.attacker.com", false},
		{"localhost.localdomain", false},
		{"attacker-localhost", false},
		{"127.0.0.1.nip.io", false},
		{"0.0.0.0", false},
		{"::", false},
		{"10.0.0.1", false},
		{"128.0.0.1", false},
	}
	for _, tt := range tests {
		if got := isLoopbackHost(tt.host); got != tt.want {
			t.Errorf("isLoopbackHost(%q) = %v, want %v", tt.host, got, tt.want)
		}
	}
}

func TestParseAllowlist(t *testing.T) {
	tests := []struct {
		entry   string
		want    endpoint
		wantErr bool
	}{
		{entry: "api.example.com", want: endpoint{"api.example.com", ""}},
		{entry: "Api.Example.com:8443", want: endpoint{"api.example.com", "8443"}},
		{entry: "localhost:11434", want: endpoint{"localhost", "11434"}},
		{entry: "::1", want: endpoint{"::1", ""}},
		{entry: "[::1]", want: endpoint{"::1", ""}},
		{entry: "[::1]:8080", want: endpoint{"::1", "8080"}},
		{entry: "10.0.0.5:8443", want: endpoint{"10.0.0.5", "8443"}},
		{entry: "example.com:0", wantErr: true},
		{entry: "example.com:65536", wantErr: true},
		{entry: "example.com:0443", wantErr: true},
		{entry: "example.com:", wantErr: true},
		{entry: "2130706433", wantErr: true},
		{entry: "[::1", wantErr: true},
		{entry: "", wantErr: true},
	}
	for _, tt := range tests {
		a, err := parseAllowlist([]string{tt.entry})
		if (err != nil) != tt.wantErr {
			t.Errorf("parseAllowlist(%q) err = %v, wantErr %v", tt.entry, err, tt.wantErr)
			continue
		}
		if err == nil && !a.endpoints[tt.want] {
			t.Errorf("parseAllowlist(%q) = %v, want entry %v", tt.entry, a.endpoints, tt.want)
		}
	}
}

func TestPublicAddr(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"93.184.216.34", true},
		{"198.51.100.7", false}, // TEST-NET-2, see TestPublicAddrRefusesTestRanges
		{"2606:4700::1111", true},
		{"64:ff9b::5db8:d822", true}, // NAT64 of a public IPv4
		{"169.254.169.254", false},   // cloud metadata
		{"fd00:ec2::254", false},     // AWS IPv6 metadata
		{"127.0.0.1", false},
		{"127.8.9.10", false},
		{"::1", false},
		{"0.0.0.0", false},
		{"::", false},
		{"10.1.2.3", false},
		{"172.16.0.1", false},
		{"172.31.255.255", false},
		{"192.168.1.1", false},
		{"100.64.0.1", false},
		{"::ffff:10.0.0.1", false}, // IPv4-mapped private
		{"::ffff:169.254.169.254", false},
		{"::7f00:1", false},             // IPv4-compatible loopback
		{"64:ff9b::a9fe:a9fe", false},   // NAT64 of 169.254.169.254
		{"64:ff9b::7f00:1", false},      // NAT64 of 127.0.0.1
		{"::ffff:0:7f00:1", false},      // SIIT of 127.0.0.1
		{"::ffff:0:a9fe:a9fe", false},   // SIIT of 169.254.169.254
		{"::ffff:0:a00:1", false},       // SIIT of 10.0.0.1
		{"::ffff:0:5db8:d822", true},    // SIIT of a public IPv4
		{"64:ff9b:1::a9fe:a9fe", false}, // local-use NAT64
		{"168.63.129.16", false},        // Azure WireServer
		{"2002:7f00:1::", false},        // 6to4 of 127.0.0.1
		{"fe80::1", false},
		{"fc00::1", false},
		{"ff02::1", false},
		{"224.0.0.1", false},
		{"255.255.255.255", false},
	}
	for _, tt := range tests {
		if got := publicAddr(netip.MustParseAddr(tt.ip)); got != tt.want {
			t.Errorf("publicAddr(%s) = %v, want %v", tt.ip, got, tt.want)
		}
	}
}

// Acceptance (#111): documentation, test and benchmarking ranges are
// refused at both ends, in every embedding the gateway decodes, and the
// addresses just outside each range stay public, so no refusal is wider
// than its RFC.
func TestPublicAddrRefusesTestRanges(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		// TEST-NET-1, -2, -3 (RFC 5737)
		{"192.0.2.0", false}, {"192.0.2.255", false}, {"192.0.1.255", true}, {"192.0.3.0", true},
		{"198.51.100.0", false}, {"198.51.100.255", false}, {"198.51.99.255", true}, {"198.51.101.0", true},
		{"203.0.113.0", false}, {"203.0.113.255", false}, {"203.0.112.255", true}, {"203.0.114.0", true},
		// IPv4 benchmarking (RFC 2544)
		{"198.18.0.0", false}, {"198.19.255.255", false}, {"198.17.255.255", true}, {"198.20.0.0", true},
		// IPv6 documentation (RFC 3849, RFC 9637)
		{"2001:db8::", false}, {"2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", false},
		{"2001:db7:ffff:ffff:ffff:ffff:ffff:ffff", true}, {"2001:db9::", true},
		{"3fff::", false}, {"3fff:fff:ffff:ffff:ffff:ffff:ffff:ffff", false},
		{"3ffe:ffff:ffff:ffff:ffff:ffff:ffff:ffff", true}, {"3fff:1000::", true},
		// IPv6 benchmarking (RFC 5180)
		{"2001:2::", false}, {"2001:2:0:ffff:ffff:ffff:ffff:ffff", false},
		{"2001:1:ffff:ffff:ffff:ffff:ffff:ffff", true}, {"2001:2:1::", true},
		// SRv6 SIDs (RFC 9602)
		{"5f00::", false}, {"5f00:ffff:ffff:ffff:ffff:ffff:ffff:ffff", false},
		{"5eff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", true}, {"5f01::", true},
		// The same ranges reached through an embedding
		{"::ffff:192.0.2.1", false},        // IPv4-mapped TEST-NET-1
		{"::ffff:198.18.0.1", false},       // IPv4-mapped benchmarking
		{"64:ff9b::cb00:7101", false},      // NAT64 of 203.0.113.1
		{"::ffff:0:c633:6401", false},      // SIIT of 198.51.100.1
		{"2001:db8:64::7f00:1", false},     // NAT64 network-specific prefix in documentation space
		{"2001:470::5efe:c000:201", false}, // ISATAP of 192.0.2.1
	}
	for _, tt := range tests {
		if got := publicAddr(netip.MustParseAddr(tt.ip)); got != tt.want {
			t.Errorf("publicAddr(%s) = %v, want %v", tt.ip, got, tt.want)
		}
	}
}

// ISATAP interface IDs ([00|02]00:5efe:w.x.y.z, u/g bits allowed) are judged
// by the IPv4 they embed as well as by their prefix. A network-specific
// NAT64 prefix outside documentation space cannot be recognized and stays
// public: a known limit, documented in doc.go.
func TestPublicAddrISATAP(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"2001:470::5efe:7f00:1", false},        // 127.0.0.1
		{"2001:470::200:5efe:a9fe:a9fe", false}, // 169.254.169.254, universal bit
		{"2001:470::100:5efe:a00:1", false},     // 10.0.0.1, group bit
		{"2001:470::300:5efe:c0a8:101", false},  // 192.168.1.1, both bits
		{"2001:470::5efe:5db8:d822", true},      // a public IPv4
		{"2001:470::400:5efe:a00:1", true},      // first byte not 00-03: not ISATAP
		{"2001:470::1:5efe:a00:1", true},        // second byte not 00: not ISATAP
		{"2001:470::5dfe:a00:1", true},          // 5d, not 5e: not ISATAP
		{"2001:470::5eff:a00:1", true},          // not 5efe: not ISATAP
		{"fe80::5efe:5db8:d822", false},         // public IPv4, link-local prefix
		{"2001:470:64::7f00:1", true},           // undecodable NAT64 prefix: known limit
	}
	for _, tt := range tests {
		if got := publicAddr(netip.MustParseAddr(tt.ip)); got != tt.want {
			t.Errorf("publicAddr(%s) = %v, want %v", tt.ip, got, tt.want)
		}
	}
}
