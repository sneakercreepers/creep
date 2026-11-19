package main

import (
	"context"
	"net"
	"time"
)

var dialer = net.Dialer{Timeout: 3 * time.Second}

// internet is a PoC that tries to reach the internet from the run's
// network: every attempt must fail, while the database on the same network
// (the control) answers.
func internet() []string {
	var p []string
	if c, err := dialer.Dial("tcp", "db:5432"); err != nil {
		p = append(p, "database unreachable: "+err.Error())
	} else {
		_ = c.Close()
	}
	for _, addr := range []string{"1.1.1.1:443", "8.8.8.8:53", "[2606:4700:4700::1111]:443"} {
		if c, err := dialer.Dial("tcp", addr); err == nil {
			_ = c.Close()
			p = append(p, "reached "+addr)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if _, err := net.DefaultResolver.LookupHost(ctx, "example.com"); err == nil {
		p = append(p, "resolved example.com")
	}
	direct := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return dialer.DialContext(ctx, "udp", "1.1.1.1:53")
	}}
	if _, err := direct.LookupHost(ctx, "example.com"); err == nil {
		p = append(p, "resolved example.com through 1.1.1.1")
	}
	return p
}

// dial reports whether a TCP connection to addr opens.
func dial(addr string) string {
	c, err := dialer.Dial("tcp", addr)
	if err != nil {
		return "unreachable"
	}
	_ = c.Close()
	return "reachable"
}
