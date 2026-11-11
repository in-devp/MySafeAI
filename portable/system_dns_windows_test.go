package main

import (
	"net/netip"
	"slices"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestAdapterNameServers(t *testing.T) {
	dns4 := windows.RawSockaddrInet4{Family: windows.AF_INET, Addr: [4]byte{192, 0, 2, 53}}
	address4 := windows.SocketAddress{
		Sockaddr:       (*syscall.RawSockaddrAny)(unsafe.Pointer(&dns4)),
		SockaddrLength: int32(unsafe.Sizeof(dns4)),
	}
	dns6 := windows.RawSockaddrInet6{Family: windows.AF_INET6, Addr: netip.MustParseAddr("fe80::53").As16()}
	address6 := windows.SocketAddress{
		Sockaddr:       (*syscall.RawSockaddrAny)(unsafe.Pointer(&dns6)),
		SockaddrLength: int32(unsafe.Sizeof(dns6)),
	}
	excluded := windows.RawSockaddrInet4{Family: windows.AF_INET, Addr: [4]byte{198, 51, 100, 53}}
	excludedServer := windows.IpAdapterDnsServerAdapter{Address: windows.SocketAddress{
		Sockaddr:       (*syscall.RawSockaddrAny)(unsafe.Pointer(&excluded)),
		SockaddrLength: int32(unsafe.Sizeof(excluded)),
	}}
	v4 := windows.IpAdapterDnsServerAdapter{Address: address4}
	v6 := windows.IpAdapterDnsServerAdapter{Address: address6, Next: &v4}
	loopback := windows.IpAdapterAddresses{
		OperStatus: windows.IfOperStatusUp, IfType: windows.IF_TYPE_SOFTWARE_LOOPBACK, FirstDnsServerAddress: &excludedServer,
	}
	down := windows.IpAdapterAddresses{
		OperStatus: windows.IfOperStatusDown, FirstDnsServerAddress: &v6, Next: &loopback,
	}
	up := windows.IpAdapterAddresses{
		OperStatus: windows.IfOperStatusUp, Ipv6IfIndex: 7, FirstDnsServerAddress: &v6, Next: &down,
	}
	want := []netip.Addr{netip.MustParseAddr("fe80::53%7"), netip.MustParseAddr("192.0.2.53")}
	if got := adapterNameServers(&up); !slices.Equal(got, want) {
		t.Fatalf("servers = %v, want %v", got, want)
	}
}
