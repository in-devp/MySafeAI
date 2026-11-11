package main

import (
	"context"
	"errors"
	"net/netip"
	"runtime"
	"strconv"
	"unsafe"

	"golang.org/x/sys/windows"
)

func systemNameServers(ctx context.Context) ([]netip.Addr, error) {
	const flags = windows.GAA_FLAG_SKIP_UNICAST | windows.GAA_FLAG_SKIP_ANYCAST |
		windows.GAA_FLAG_SKIP_MULTICAST | windows.GAA_FLAG_SKIP_FRIENDLY_NAME
	var size uint32 = 15 * 1024
	for range 3 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		buffer := make([]byte, size)
		first := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buffer[0]))
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, flags, 0, first, &size)
		if errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) {
			continue
		}
		if errors.Is(err, windows.ERROR_NO_DATA) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		servers := adapterNameServers(first)
		runtime.KeepAlive(buffer)
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return servers, nil
	}
	return nil, windows.ERROR_BUFFER_OVERFLOW
}

func adapterNameServers(first *windows.IpAdapterAddresses) []netip.Addr {
	var servers []netip.Addr
	seen := make(map[netip.Addr]bool)
	for adapter := first; adapter != nil; adapter = adapter.Next {
		if adapter.OperStatus != windows.IfOperStatusUp || adapter.IfType == windows.IF_TYPE_SOFTWARE_LOOPBACK {
			continue
		}
		for node := adapter.FirstDnsServerAddress; node != nil; node = node.Next {
			if node.Address.Sockaddr == nil || node.Address.SockaddrLength <= 0 {
				continue
			}
			address, ok := netip.AddrFromSlice(node.Address.IP())
			if !ok {
				continue
			}
			if address.Is6() && address.IsLinkLocalUnicast() {
				sockaddr := (*windows.RawSockaddrInet6)(unsafe.Pointer(node.Address.Sockaddr))
				scope := sockaddr.Scope_id
				if scope == 0 {
					scope = adapter.Ipv6IfIndex
				}
				if scope != 0 {
					address = address.WithZone(strconv.FormatUint(uint64(scope), 10))
				}
			}
			address = address.Unmap()
			if !seen[address] {
				seen[address] = true
				servers = append(servers, address)
			}
		}
	}
	return servers
}
