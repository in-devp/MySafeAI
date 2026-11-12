package main

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"
)

var noRoute = errors.New("no route")

type config struct {
	Adapter               string                       `json:"adapter"`
	Allowed               []string                     `json:"allowed"`
	DirectAllowed         []string                     `json:"directAllowed,omitempty"`
	Countries             []string                     `json:"countries,omitempty"`
	Rules                 map[string]appConnectionRule `json:"rules,omitempty"`
	TrustedNetworks       []trustedNetwork             `json:"trustedNetworks,omitempty"`
	Sources               []sourcePreference           `json:"sources,omitempty"`
	DisabledSources       []string                     `json:"disabledSources,omitempty"`
	Targets               []string                     `json:"targets"`
	CustomTargets         []appTarget                  `json:"customTargets,omitempty"`
	Watch                 *bool                        `json:"watch,omitempty"`
	CloseAfterDelay       bool                         `json:"closeAfterDelay,omitempty"`
	BlockOutsideDNS       bool                         `json:"blockOutsideDNS,omitempty"`
	ObserveDNS            bool                         `json:"observeDNS,omitempty"`
	Notifications         bool                         `json:"notifications,omitempty"`
	ProtectionDisabled    bool                         `json:"protectionDisabled,omitempty"`
	ProtectionPausedUntil *time.Time                   `json:"protectionPausedUntil,omitempty"`
}

func (c config) protectionState(now time.Time) string {
	if c.ProtectionDisabled {
		return "disabled"
	}
	if c.ProtectionPausedUntil != nil && now.Before(*c.ProtectionPausedUntil) {
		return "suspended"
	}
	return ""
}

func (c config) allows(ip netip.Addr) bool {
	return addressAllowed(c.Allowed, ip)
}

type probe struct {
	Name      string `json:"name"`
	IP        string `json:"ip,omitempty"`
	Err       string `json:"error,omitempty"`
	host      string
	ipv6      bool
	usedProxy bool
}

type report struct {
	Adapter  string   `json:"adapter"`
	IPv6     bool     `json:"ipv6"`
	IPs      []string `json:"ips,omitempty"`
	Probes   []probe  `json:"probes,omitempty"`
	Trusted  bool     `json:"trusted"`
	Reason   string   `json:"reason"`
	Mode     string   `json:"mode,omitempty"`
	routeKey string
	target   string
}

var (
	anchors4 = []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("8.8.8.8")}
	anchors6 = []netip.Addr{netip.MustParseAddr("2606:4700:4700::1111"), netip.MustParseAddr("2001:4860:4860::8888")}
)

func routes(ctx context.Context, adapter string) (bool, error) {
	for _, ip := range anchors4 {
		actual, err := routeFor(ctx, ip)
		if err != nil {
			return false, fmt.Errorf("IPv4 route to %s: %w", ip, err)
		}
		if actual != adapter {
			return false, fmt.Errorf("IPv4 uses %s instead of %s", actual, adapter)
		}
	}
	return ipv6Tunnel(ctx, adapter)
}

func ipv6Tunnel(ctx context.Context, adapter string) (bool, error) {
	available := false
	for _, ip := range anchors6 {
		actual, err := routeFor(ctx, ip)
		if errors.Is(err, noRoute) {
			continue
		}
		if err != nil {
			return false, fmt.Errorf("IPv6 route to %s: %w", ip, err)
		}
		if actual != adapter {
			return false, fmt.Errorf("IPv6 uses %s instead of %s", actual, adapter)
		}
		available = true
	}
	return available, nil
}

type provider struct {
	name, url string
	v6, trace bool
}

var providers = []provider{
	{"AWS", "https://checkip.amazonaws.com/", false, false},
	{"Cloudflare", "https://1.1.1.1/cdn-cgi/trace", false, true},
	{"ipify IPv6", "https://api6.ipify.org/", true, false},
	{"ident.me IPv6", "https://6.ident.me/", true, false},
}

func sourceNames() []string {
	names := make([]string, len(providers))
	for i, source := range providers {
		names[i] = source.name
	}
	return names
}

func assess(c config, probes []probe) ([]string, string) {
	if len(probes) != 2 && len(probes) != 4 {
		return nil, "incomplete IP checks"
	}
	var confirmed []string
	for i := 0; i < len(probes); i += 2 {
		if probes[i].IP == "" || probes[i+1].IP == "" {
			return nil, "two independent providers must confirm each available IP family"
		}
		if probes[i].IP != probes[i+1].IP {
			return nil, "IP providers disagree"
		}
		ip, err := netip.ParseAddr(probes[i].IP)
		if err != nil || ip.Is4() != (i == 0) {
			return nil, "unexpected address family"
		}
		confirmed = append(confirmed, ip.String())
	}
	for _, value := range confirmed {
		if !c.allows(netip.MustParseAddr(value)) {
			return confirmed, "verified IP is outside your allowlist"
		}
	}
	return confirmed, ""
}
