package main

import (
	"context"
	"net/netip"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsRoutePreservesIPv6Scope(t *testing.T) {
	address, err := windowsRouteAddress(netip.MustParseAddr("fe80::53%7"))
	if err != nil {
		t.Fatal(err)
	}
	v6, ok := address.(*windows.SockaddrInet6)
	if !ok || v6.ZoneId != 7 || v6.Addr != netip.MustParseAddr("fe80::53").As16() {
		t.Fatalf("scoped DNS address was changed: %#v", address)
	}
	if _, err := windowsRouteAddress(netip.MustParseAddr("fe80::53")); err == nil {
		t.Fatal("an ambiguous link-local DNS route was accepted without its interface")
	}
	if _, err := windowsRouteAddress(netip.Addr{}); err == nil {
		t.Fatal("an invalid route address was accepted")
	}
	v4, err := windowsRouteAddress(netip.MustParseAddr("::ffff:192.0.2.1"))
	if err != nil || v4.(*windows.SockaddrInet4).Addr != [4]byte{192, 0, 2, 1} {
		t.Fatalf("IPv4-mapped address: %#v, %v", v4, err)
	}
}

func TestWindowsRouteResolvesSingleInterface(t *testing.T) {
	name, err := routeFor(context.Background(), netip.MustParseAddr("127.0.0.1"))
	if err != nil || name == "" {
		t.Fatalf("loopback route lookup failed: name=%q err=%v", name, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := routeFor(ctx, netip.MustParseAddr("127.0.0.1")); err != context.Canceled {
		t.Fatalf("cancelled route lookup returned %v", err)
	}
}

func BenchmarkWindowsRouteLookup(b *testing.B) {
	ctx := context.Background()
	address := netip.MustParseAddr("127.0.0.1")
	b.ReportAllocs()
	for b.Loop() {
		if _, err := routeFor(ctx, address); err != nil {
			b.Fatal(err)
		}
	}
}
