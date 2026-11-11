package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
)

func routeFor(ctx context.Context, address netip.Addr) (string, error) {
	family := "-4"
	if address.Is6() {
		family = "-6"
	}
	cmd := exec.CommandContext(ctx, "ip", "-json", family, "route", "get", address.String())
	cmd.Env = append(cmd.Environ(), "LC_ALL=C")
	data, err := cmd.CombinedOutput()
	if err != nil {
		if strings.TrimSpace(string(data)) == "RTNETLINK answers: Network is unreachable" {
			return "", noRoute
		}
		return "", fmt.Errorf("ip route get: %w", err)
	}
	var routes []struct {
		Device string `json:"dev"`
	}
	if err := json.Unmarshal(data, &routes); err != nil || len(routes) != 1 || routes[0].Device == "" {
		return "", fmt.Errorf("route to %s is ambiguous", address)
	}
	return routes[0].Device, nil
}
