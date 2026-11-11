//go:build linux || freebsd

package main

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"
)

func systemNameServers(ctx context.Context) ([]netip.Addr, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	file, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return nil, err
	}
	defer file.Close()
	servers, err := parseResolverConfig(file)
	if err != nil {
		return nil, err
	}
	if runtime.GOOS == "linux" && hasResolvedStub(servers) {
		servers = resolvedNameServers(ctx, servers)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return servers, nil
}

func parseResolverConfig(reader io.Reader) ([]netip.Addr, error) {
	scanner := bufio.NewScanner(reader)
	var servers []netip.Addr
	seen := make(map[netip.Addr]bool)
	for scanner.Scan() {
		line := scanner.Text()
		if comment := strings.IndexAny(line, "#;"); comment >= 0 {
			line = line[:comment]
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		if address, err := netip.ParseAddr(fields[1]); err == nil {
			address = address.Unmap()
			if !seen[address] {
				seen[address] = true
				servers = append(servers, address)
			}
		}
	}
	return servers, scanner.Err()
}

func isResolvedStub(address netip.Addr) bool {
	return address == netip.AddrFrom4([4]byte{127, 0, 0, 53}) ||
		address == netip.AddrFrom4([4]byte{127, 0, 0, 54})
}

func hasResolvedStub(servers []netip.Addr) bool {
	for _, address := range servers {
		if isResolvedStub(address) {
			return true
		}
	}
	return false
}

func resolvedNameServers(ctx context.Context, configured []netip.Addr) []netip.Addr {
	conn, err := dbus.SystemBus()
	if err != nil {
		return configured
	}
	const service = "org.freedesktop.resolve1"
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var property dbus.Variant
	err = conn.Object(service, "/org/freedesktop/resolve1").
		CallWithContext(ctx, "org.freedesktop.DBus.Properties.Get", dbus.FlagNoAutoStart, service+".Manager", "DNS").
		Store(&property)
	if err != nil {
		return configured
	}
	var entries []struct {
		Interface int32
		Family    int32
		Address   []byte
	}
	if err := dbus.Store([]any{property.Value()}, &entries); err != nil {
		return configured
	}
	var servers []netip.Addr
	seen := make(map[netip.Addr]bool)
	for _, entry := range entries {
		address, ok := netip.AddrFromSlice(entry.Address)
		if !ok || !(entry.Family == unix.AF_INET && address.Is4() ||
			entry.Family == unix.AF_INET6 && address.Is6()) {
			continue
		}
		if address.Is6() && address.IsLinkLocalUnicast() && entry.Interface > 0 {
			zone := strconv.Itoa(int(entry.Interface))
			if iface, err := net.InterfaceByIndex(int(entry.Interface)); err == nil {
				zone = iface.Name
			}
			address = address.WithZone(zone)
		}
		address = address.Unmap()
		if !isResolvedStub(address) && !seen[address] {
			seen[address] = true
			servers = append(servers, address)
		}
	}
	if len(servers) == 0 {
		return configured
	}
	for _, address := range configured {
		if !isResolvedStub(address) && !seen[address] {
			servers = append(servers, address)
		}
	}
	return servers
}
