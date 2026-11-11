//go:build linux || freebsd

package main

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
)

func TestParseResolverConfig(t *testing.T) {
	servers, err := parseResolverConfig(strings.NewReader(`
		# nameserver 8.8.4.4
		search corp.example
		nameserver 127.0.0.53
		nameserver 192.0.2.53# inline comment
		nameserver ::ffff:192.0.2.53
		nameserver fe80::1%eth0 ; IPv6 link-local scope
		nameserver 2001:db8::53
		nameserver resolver.example
		nameserver 203.0.113.53 extra-field
	`))
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.Addr{
		netip.MustParseAddr("127.0.0.53"),
		netip.MustParseAddr("192.0.2.53"),
		netip.MustParseAddr("fe80::1%eth0"),
		netip.MustParseAddr("2001:db8::53"),
		netip.MustParseAddr("203.0.113.53"),
	}
	if !slices.Equal(servers, want) {
		t.Fatalf("servers = %v, want %v", servers, want)
	}
	if !hasResolvedStub(servers) || hasResolvedStub(servers[1:]) {
		t.Fatal("unexpected systemd-resolved stub detection")
	}
}
