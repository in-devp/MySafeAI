package main

import (
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
)

func routeFor(ctx context.Context, address netip.Addr) (string, error) {
	family := "-inet"
	if address.Is6() {
		family = "-inet6"
	}
	cmd := exec.CommandContext(ctx, "/sbin/route", "-n", "get", family, address.String())
	cmd.Env = append(cmd.Environ(), "LC_ALL=C")
	data, err := cmd.CombinedOutput()
	output := string(data)
	if strings.Contains(output, "route has not been found") ||
		strings.Contains(output, "Network is unreachable") ||
		strings.Contains(output, "not in table") {
		return "", noRoute
	}
	if err != nil {
		return "", fmt.Errorf("route get: %w", err)
	}
	var device string
	for line := range strings.Lines(output) {
		key, value, found := strings.Cut(strings.TrimSpace(line), ":")
		if !found {
			continue
		}
		if key == "interface" {
			device = strings.TrimSpace(value)
		}
		if key == "flags" && (strings.Contains(value, "REJECT") || strings.Contains(value, "BLACKHOLE")) {
			return "", fmt.Errorf("route to %s rejects traffic", address)
		}
	}
	if device == "" {
		return "", fmt.Errorf("route to %s has no interface", address)
	}
	return device, nil
}
