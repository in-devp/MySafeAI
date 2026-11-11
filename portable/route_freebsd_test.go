package main

import (
	"context"
	"net/netip"
	"testing"
)

func TestFreeBSDLoopbackRoute(t *testing.T) {
	device, err := routeFor(context.Background(), netip.MustParseAddr("127.0.0.1"))
	if err != nil || device != "lo0" {
		t.Fatalf("expected lo0, got %q: %v", device, err)
	}
}
