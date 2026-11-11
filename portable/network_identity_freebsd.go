package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"slices"
	"strings"

	"golang.org/x/sys/unix"
)

func localNetworkIdentity(ctx context.Context) (string, string, error) {
	route, err := matchingLocalRoute(ctx, freeBSDLocalRoute)
	if err != nil {
		return "", "", err
	}
	iface, err := net.InterfaceByName(route.adapter)
	if err != nil {
		return "", "", err
	}
	if iface.Flags&(net.FlagUp|net.FlagRunning) != net.FlagUp|net.FlagRunning ||
		iface.Flags&(net.FlagLoopback|net.FlagPointToPoint) != 0 || !validGatewayMAC(iface.HardwareAddr) ||
		strings.HasPrefix(iface.Name, "-") {
		return "", "", errors.New("IPv4 route does not use an active Ethernet or Wi-Fi interface")
	}
	cmd := exec.CommandContext(ctx, "/sbin/ifconfig", "-n", "-v", iface.Name)
	cmd.Env = append(cmd.Environ(), "LC_ALL=C")
	data, err := cmd.Output()
	if err != nil {
		return "", "", fmt.Errorf("ifconfig: %w", err)
	}
	device, err := freeBSDPhysicalDevice(data)
	if err != nil {
		return "", "", err
	}
	driver := strings.TrimRight(device, "0123456789")
	unit := strings.TrimPrefix(device, driver)
	if driver == "" || unit == "" || strings.ContainsAny(driver, "./\\ \t") {
		return "", "", errors.New("IPv4 route has no usable physical device")
	}
	// Hardware NICs have a newbus device. A cloned wlan interface must
	// name its hardware parent rather than relying on the cloned name.
	registered, err := unix.Sysctl("dev." + driver + "." + unit + ".%driver")
	if err != nil || registered != driver {
		return "", "", errors.New("IPv4 route does not use a physical interface")
	}

	cmd = exec.CommandContext(ctx, "/usr/sbin/arp", "--libxo", "json", "-n", "-i", iface.Name, route.gateway.String())
	cmd.Env = append(cmd.Environ(), "LC_ALL=C")
	data, err = cmd.Output()
	if err != nil {
		return "", "", fmt.Errorf("arp: %w", err)
	}
	mac, err := parseFreeBSDGateway(data, route)
	if err != nil {
		return "", "", err
	}
	current, err := matchingLocalRoute(ctx, freeBSDLocalRoute)
	if err != nil || current != route {
		return "", "", errors.New("IPv4 gateway changed during identification")
	}
	return gatewayFingerprint(device+"/"+iface.Name+"/"+iface.HardwareAddr.String(), route.gateway, mac), iface.Name, nil
}

func freeBSDPhysicalDevice(data []byte) (string, error) {
	var status, media, driver, parent string
	for line := range strings.Lines(string(data)) {
		key, value, found := strings.Cut(strings.TrimSpace(line), ":")
		if !found {
			continue
		}
		value = strings.TrimSpace(value)
		switch key {
		case "status":
			status = value
		case "media":
			media = value
		case "drivername":
			driver = value
		case "parent interface":
			parent = value
		}
	}
	if strings.HasPrefix(media, "Ethernet ") && status == "active" && driver != "" {
		return driver, nil
	}
	if strings.HasPrefix(media, "IEEE 802.11 ") && status == "associated" && parent != "" {
		return parent, nil
	}
	return "", errors.New("IPv4 route does not use an active Ethernet or Wi-Fi device")
}

func freeBSDLocalRoute(ctx context.Context, address netip.Addr) (localIPv4Route, error) {
	cmd := exec.CommandContext(ctx, "/sbin/route", "-n", "get", "-inet", address.String())
	cmd.Env = append(cmd.Environ(), "LC_ALL=C")
	data, err := cmd.Output()
	if err != nil {
		return localIPv4Route{}, fmt.Errorf("route get: %w", err)
	}
	return parseFreeBSDLocalRoute(data)
}

func parseFreeBSDLocalRoute(data []byte) (localIPv4Route, error) {
	var route localIPv4Route
	var flags []string
	for line := range strings.Lines(string(data)) {
		key, value, found := strings.Cut(strings.TrimSpace(line), ":")
		if !found {
			continue
		}
		value = strings.TrimSpace(value)
		switch key {
		case "interface":
			if route.adapter != "" {
				return localIPv4Route{}, errors.New("IPv4 route has multiple interfaces")
			}
			route.adapter = value
		case "gateway":
			if route.gateway.IsValid() {
				return localIPv4Route{}, errors.New("IPv4 route has multiple gateways")
			}
			gateway, err := netip.ParseAddr(value)
			if err != nil {
				return localIPv4Route{}, errors.New("IPv4 route has no gateway")
			}
			route.gateway = gateway
		case "flags":
			flags = strings.Split(strings.Trim(value, "<>"), ",")
		}
	}
	if !slices.Contains(flags, "GATEWAY") || slices.Contains(flags, "REJECT") || slices.Contains(flags, "BLACKHOLE") {
		return localIPv4Route{}, errors.New("IPv4 route has no usable gateway")
	}
	return route, nil
}

func parseFreeBSDGateway(data []byte, route localIPv4Route) (net.HardwareAddr, error) {
	var response struct {
		ARP struct {
			Entries []struct {
				Address    string `json:"ip-address"`
				Device     string `json:"interface"`
				MAC        string `json:"mac-address"`
				Incomplete bool   `json:"incomplete"`
				Expired    bool   `json:"expired"`
				Published  bool   `json:"published"`
				Permanent  bool   `json:"permanent"`
			} `json:"arp-cache"`
		} `json:"arp"`
	}
	if err := json.Unmarshal(data, &response); err != nil || len(response.ARP.Entries) != 1 {
		return nil, errors.New("IPv4 gateway has no unique cached neighbor")
	}
	entry := response.ARP.Entries[0]
	if entry.Address != route.gateway.String() || entry.Device != route.adapter ||
		entry.Incomplete || entry.Expired || entry.Published || entry.Permanent {
		return nil, errors.New("IPv4 gateway neighbor is unavailable")
	}
	mac, err := net.ParseMAC(entry.MAC)
	if err != nil || !validGatewayMAC(mac) {
		return nil, errors.New("IPv4 gateway has no valid Ethernet address")
	}
	return mac, nil
}
