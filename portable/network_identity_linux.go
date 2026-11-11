package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
)

func localNetworkIdentity(ctx context.Context) (string, string, error) {
	route, err := matchingLocalRoute(ctx, linuxLocalRoute)
	if err != nil {
		return "", "", err
	}
	iface, err := net.InterfaceByName(route.adapter)
	if err != nil {
		return "", "", err
	}
	if iface.Flags&(net.FlagUp|net.FlagRunning) != net.FlagUp|net.FlagRunning ||
		iface.Flags&(net.FlagLoopback|net.FlagPointToPoint) != 0 || !validGatewayMAC(iface.HardwareAddr) ||
		filepath.Base(iface.Name) != iface.Name {
		return "", "", errors.New("IPv4 route does not use an active Ethernet or Wi-Fi interface")
	}
	// A kernel device link distinguishes Ethernet and Wi-Fi devices from
	// software interfaces such as bridges, TAP, and WireGuard.
	if _, err := os.Stat(filepath.Join("/sys/class/net", iface.Name, "device")); err != nil {
		return "", "", errors.New("IPv4 route does not use a physical interface")
	}

	cmd := exec.CommandContext(ctx, "ip", "-json", "-4", "neigh", "show", "to", route.gateway.String(), "dev", iface.Name)
	cmd.Env = append(cmd.Environ(), "LC_ALL=C")
	data, err := cmd.Output()
	if err != nil {
		return "", "", fmt.Errorf("ip neigh show: %w", err)
	}
	mac, err := parseLinuxGateway(data, route)
	if err != nil {
		return "", "", err
	}
	current, err := matchingLocalRoute(ctx, linuxLocalRoute)
	if err != nil || current != route {
		return "", "", errors.New("IPv4 gateway changed during identification")
	}
	return gatewayFingerprint(iface.Name+"/"+iface.HardwareAddr.String(), route.gateway, mac), iface.Name, nil
}

func linuxLocalRoute(ctx context.Context, address netip.Addr) (localIPv4Route, error) {
	cmd := exec.CommandContext(ctx, "ip", "-json", "-4", "route", "get", address.String())
	cmd.Env = append(cmd.Environ(), "LC_ALL=C")
	data, err := cmd.Output()
	if err != nil {
		return localIPv4Route{}, fmt.Errorf("ip route get: %w", err)
	}
	return parseLinuxLocalRoute(data)
}

func parseLinuxLocalRoute(data []byte) (localIPv4Route, error) {
	var routes []struct {
		Device  string `json:"dev"`
		Gateway string `json:"gateway"`
		Type    string `json:"type"`
	}
	if err := json.Unmarshal(data, &routes); err != nil || len(routes) != 1 ||
		(routes[0].Type != "" && routes[0].Type != "unicast") {
		return localIPv4Route{}, errors.New("IPv4 route is not a unique unicast route")
	}
	gateway, err := netip.ParseAddr(routes[0].Gateway)
	if err != nil {
		return localIPv4Route{}, errors.New("IPv4 route has no gateway")
	}
	return localIPv4Route{adapter: routes[0].Device, gateway: gateway}, nil
}

func parseLinuxGateway(data []byte, route localIPv4Route) (net.HardwareAddr, error) {
	var entries []struct {
		Address string          `json:"dst"`
		Device  string          `json:"dev"`
		MAC     string          `json:"lladdr"`
		State   []string        `json:"state"`
		Proxy   json.RawMessage `json:"proxy"`
	}
	if err := json.Unmarshal(data, &entries); err != nil || len(entries) != 1 {
		return nil, errors.New("IPv4 gateway has no unique cached neighbor")
	}
	entry := entries[0]
	if entry.Address != route.gateway.String() || (entry.Device != "" && entry.Device != route.adapter) ||
		len(entry.State) != 1 || !slices.Contains([]string{"REACHABLE", "STALE", "DELAY", "PROBE"}, entry.State[0]) ||
		entry.Proxy != nil {
		return nil, errors.New("IPv4 gateway neighbor is unavailable")
	}
	mac, err := net.ParseMAC(entry.MAC)
	if err != nil || !validGatewayMAC(mac) {
		return nil, errors.New("IPv4 gateway has no valid Ethernet address")
	}
	return mac, nil
}
