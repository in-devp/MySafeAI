package main

import (
	"net/netip"
	"testing"
	"unsafe"
)

// Match the Windows SDK layouts used by the dynamically loaded IP Helper APIs.
const (
	gatewayRouteRowSize    = 104
	gatewayNeighborRowSize = 88
)

var (
	_ [gatewayRouteRowSize - unsafe.Sizeof(gatewayWindowsRouteRow{})]byte
	_ [unsafe.Sizeof(gatewayWindowsRouteRow{}) - gatewayRouteRowSize]byte
	_ [gatewayNeighborRowSize - unsafe.Sizeof(gatewayWindowsNeighborRow{})]byte
	_ [unsafe.Sizeof(gatewayWindowsNeighborRow{}) - gatewayNeighborRowSize]byte
)

func TestWindowsIPv4GatewaySockaddr(t *testing.T) {
	ip := netip.MustParseAddr("192.168.1.15")
	sockaddr := makeGatewaySockaddr(ip)
	raw := (*[28]byte)(unsafe.Pointer(&sockaddr))
	if [4]byte(raw[4:8]) != ip.As4() || sockaddr.address() != ip {
		t.Fatalf("unexpected network-order sockaddr %v", sockaddr)
	}
}
