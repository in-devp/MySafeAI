package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"

	"golang.org/x/sys/windows"
)

func windowsRouteAddress(address netip.Addr) (windows.Sockaddr, error) {
	if !address.IsValid() {
		return nil, errors.New("invalid route address")
	}
	address = address.Unmap()
	if address.Is4() {
		return &windows.SockaddrInet4{Addr: address.As4()}, nil
	}
	var scope uint32
	if zone := address.Zone(); zone != "" {
		index, err := strconv.ParseUint(zone, 10, 32)
		if err == nil {
			scope = uint32(index)
		} else {
			iface, lookupErr := net.InterfaceByName(zone)
			if lookupErr != nil {
				return nil, fmt.Errorf("resolve IPv6 interface scope: %w", lookupErr)
			}
			scope = uint32(iface.Index)
		}
	}
	if address.IsLinkLocalUnicast() && scope == 0 {
		return nil, errors.New("link-local IPv6 route requires an interface scope")
	}
	return &windows.SockaddrInet6{Addr: address.As16(), ZoneId: scope}, nil
}

func routeFor(ctx context.Context, address netip.Addr) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	addressInfo, err := windowsRouteAddress(address)
	if err != nil {
		return "", err
	}
	var index uint32
	if err := windows.GetBestInterfaceEx(addressInfo, &index); err != nil {
		if errors.Is(err, windows.ERROR_NOT_FOUND) || errors.Is(err, windows.ERROR_NETWORK_UNREACHABLE) ||
			errors.Is(err, windows.ERROR_HOST_UNREACHABLE) {
			return "", noRoute
		}
		return "", fmt.Errorf("GetBestInterfaceEx: %w", err)
	}
	// Route validation runs several times per second. Query only the selected
	// interface, without statistics, rather than enumerating every adapter and
	// all its addresses for every destination. Do not cache the route itself.
	row := windows.MibIfRow2{InterfaceIndex: index}
	if err := windows.GetIfEntry2Ex(windows.MibIfEntryNormalWithoutStatistics, &row); err != nil {
		return "", fmt.Errorf("GetIfEntry2Ex: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if row.InterfaceIndex != index || row.OperStatus != windows.IfOperStatusUp {
		return "", noRoute
	}
	name := windows.UTF16ToString(row.Alias[:])
	if name == "" {
		return "", fmt.Errorf("could not resolve adapter index %d", index)
	}
	return name, nil
}
