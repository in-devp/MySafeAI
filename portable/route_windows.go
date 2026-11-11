package main

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/windows"
)

func routeFor(ctx context.Context, address netip.Addr) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	var index uint32
	var addressInfo windows.Sockaddr = &windows.SockaddrInet6{Addr: address.As16()}
	if address.Is4() {
		addressInfo = &windows.SockaddrInet4{Addr: address.As4()}
	}
	if err := windows.GetBestInterfaceEx(addressInfo, &index); err != nil {
		if errors.Is(err, windows.ERROR_NOT_FOUND) || errors.Is(err, windows.ERROR_NETWORK_UNREACHABLE) ||
			errors.Is(err, windows.ERROR_HOST_UNREACHABLE) {
			return "", noRoute
		}
		return "", fmt.Errorf("GetBestInterfaceEx: %w", err)
	}
	var size uint32 = 16 * 1024
	for range 3 {
		data := make([]byte, size)
		first := (*windows.IpAdapterAddresses)(unsafe.Pointer(&data[0]))
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, windows.GAA_FLAG_INCLUDE_ALL_INTERFACES, 0, first, &size)
		if errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) {
			continue
		}
		if err != nil {
			return "", err
		}
		for adapter := first; adapter != nil; adapter = adapter.Next {
			if address.Is4() && adapter.IfIndex == index || address.Is6() && adapter.Ipv6IfIndex == index {
				return windows.UTF16PtrToString(adapter.FriendlyName), nil
			}
		}
		break
	}
	return "", fmt.Errorf("could not resolve adapter index %d", index)
}
