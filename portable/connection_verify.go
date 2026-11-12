package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"sort"
	"strings"
	"time"
)

type connectionPath struct {
	mode    connectionMode
	adapter string
	ipv6    bool
	network string
	proxies map[string]*url.URL
	hosts   []string
	key     string
}

func verify(ctx context.Context, c config) report {
	return verifyTarget(ctx, c, "global")
}

func verifyTarget(ctx context.Context, c config, target string) report {
	r := report{Adapter: c.Adapter, target: target}
	if err := c.validatePolicy(); err != nil {
		r.Reason = err.Error()
		return r
	}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	c, rule := c.forTarget(target)
	path, err := findConnectionPath(ctx, c, rule.Mode, target)
	if err != nil {
		r.Reason = err.Error()
		return r
	}
	r.Adapter, r.IPv6, r.Mode, r.routeKey = path.adapter, path.ipv6, string(path.mode), path.key
	var countries map[string]string
	if path.mode == fullTunnel || path.mode == directRoute {
		r.Probes = addressProbes(ctx, c, path.adapter, path.ipv6, false)
		r.IPs, err = consensus(r.Probes, path.ipv6)
	} else {
		r.Probes, r.IPs, countries, err = probeServicePaths(ctx, path)
	}
	if err != nil {
		r.Reason = err.Error()
		return r
	}
	if path.network != "" && networkAllows(c, path.network, r.IPs) {
		r.Trusted, r.Reason, r.Mode = true, "trusted local network verified", "local"
	} else if path.network != "" && rule.Mode != automaticMode {
		r.Reason, r.IPs = "public IP does not match the trusted local network", nil
	} else if path.mode == directRoute {
		if c.BlockOutsideDNS {
			r.Reason, r.IPs = "VPN DNS is required by the current policy", nil
		} else {
			r.Trusted = directExitAllowed(c, r.IPs)
			r.Reason = "direct IP requires approval"
			if r.Trusted {
				r.Reason = "trusted direct route verified"
			}
		}
	} else {
		r.Trusted = allowedExit(ctx, c, path.adapter, r.IPs, countries)
		r.Reason = "verified IP is outside your allowlist"
		if r.Trusted {
			r.Reason = "trusted route verified"
		}
	}
	latest, err := findConnectionPath(ctx, c, rule.Mode, target)
	if err != nil || latest.key != path.key {
		r.Trusted, r.IPs, r.Reason = false, nil, "the connection changed during verification"
	}
	return r
}

func findConnectionPath(ctx context.Context, c config, mode connectionMode, target string) (connectionPath, error) {
	path := connectionPath{adapter: c.Adapter, mode: mode}
	var identity []string
	if len(c.TrustedNetworks) != 0 {
		fingerprint, adapter, err := localNetworkIdentity(ctx)
		if err == nil && slices.ContainsFunc(c.TrustedNetworks, func(n trustedNetwork) bool { return n.Fingerprint == fingerprint }) {
			path.adapter, path.network = adapter, fingerprint
			mode, path.mode = directRoute, directRoute
		}
	}
	if mode == automaticMode {
		mode, path.mode = fullTunnel, fullTunnel
		if iface := activeRouteInterface(ctx); iface != nil && !isTunnelAdapter(*iface) {
			mode, path.mode, path.adapter = directRoute, directRoute, iface.Name
		}
	}
	if path.adapter == "" && mode != systemProxy {
		path.adapter = automaticAdapter(ctx)
		if path.adapter == "" {
			return path, errors.New("select your VPN adapter")
		}
	}
	if mode == fullTunnel || mode == directRoute {
		var err error
		path.ipv6, err = routes(ctx, path.adapter)
		if err != nil {
			return path, err
		}
	} else {
		hosts := serviceHosts(target, c.Rules[target].Host)
		if len(hosts) == 0 {
			return path, errors.New("no service routes are defined for this application")
		}
		path.proxies = make(map[string]*url.URL)
		path.hosts = hosts
		if mode == serviceTunnel {
			var err error
			path.ipv6, err = ipv6Tunnel(ctx, path.adapter)
			if err != nil {
				return path, err
			}
		}
		for _, host := range hosts {
			identity = append(identity, host)
			if mode == systemProxy {
				endpoint := serviceEndpoint(host)
				proxy, err := resolveSystemProxy(ctx, endpoint)
				if err != nil || proxy == nil {
					return path, fmt.Errorf("the system proxy is unconfirmed for %s", host)
				}
				path.proxies[host] = proxy
				identity = append(identity, proxy.String())
			} else {
				peers, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
				if err != nil || len(peers) == 0 {
					return path, fmt.Errorf("no route to %s", host)
				}
				for _, ip := range peers {
					if !usesAdapter(ctx, ip, path.adapter) {
						return path, fmt.Errorf("service %s has a route outside the selected adapter", host)
					}
					path.ipv6 = path.ipv6 || ip.Is6()
				}
			}
		}
	}
	if c.BlockOutsideDNS && mode != directRoute {
		dns := dnsRoutes(ctx, path.adapter)
		if dns.State != dnsTunnel {
			return path, errors.New("system DNS route through the VPN is unconfirmed")
		}
		identity = append(identity, dns.fingerprint())
	}
	identity = append(identity, string(mode), path.adapter, fmt.Sprint(path.ipv6), path.network)
	bytes, _ := json.Marshal(identity)
	path.key = fmt.Sprintf("%x", sha256.Sum256(bytes))
	return path, nil
}

func automaticAdapter(ctx context.Context) string {
	if iface := activeRouteInterface(ctx); iface != nil && isTunnelAdapter(*iface) {
		return iface.Name
	}
	return ""
}

func activeRouteInterface(ctx context.Context) *net.Interface {
	name, err := routeFor(ctx, anchors4[0])
	if err != nil {
		return nil
	}
	iface, err := net.InterfaceByName(name)
	if err != nil || iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
		return nil
	}
	return iface
}

func isTunnelAdapter(iface net.Interface) bool {
	lower := strings.ToLower(iface.Name)
	for _, marker := range []string{"wintun", "wireguard", "tailscale", "openvpn", "tap-windows"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	for _, prefix := range []string{"tun", "utun", "tap", "wg", "ppp"} {
		if strings.HasPrefix(lower, prefix) && strings.TrimLeft(lower[len(prefix):], "0123456789") == "" && len(lower) > len(prefix) {
			return true
		}
	}
	return iface.Flags&net.FlagPointToPoint != 0
}

func directExitAllowed(c config, ips []string) bool {
	return len(ips) > 0 && !slices.ContainsFunc(ips, func(value string) bool {
		ip, err := netip.ParseAddr(value)
		return err != nil || !slices.ContainsFunc(c.DirectAllowed, func(allowed string) bool {
			candidate, err := netip.ParseAddr(allowed)
			return err == nil && candidate == ip
		})
	})
}

func serviceEndpoint(host string) *url.URL {
	return &url.URL{Scheme: "https", Host: host, Path: "/cdn-cgi/trace"}
}

func probeServicePaths(ctx context.Context, path connectionPath) ([]probe, []string, map[string]string, error) {
	var probes []probe
	var ips []string
	countries := make(map[string]string)
	for _, host := range path.hosts {
		adapter := path.adapter
		if path.mode == systemProxy {
			adapter = ""
		}
		body, err := fetchHTTPS(ctx, serviceEndpoint(host).String(), "", adapter, path.proxies[host], 4096)
		if err != nil {
			return probes, nil, nil, fmt.Errorf("%s did not confirm its service route: %w", host, err)
		}
		trace := string(body)
		observedHost, _ := traceValue(trace, "h")
		address, _ := traceValue(trace, "ip")
		ip, err := parsePublicAddress(address)
		if observedHost != host || err != nil {
			return probes, nil, nil, fmt.Errorf("%s did not report a valid service exit IP", host)
		}
		address = ip.String()
		probes = append(probes, probe{Name: host, IP: address})
		if !slices.Contains(ips, address) {
			ips = append(ips, address)
		}
		country, _ := traceValue(trace, "loc")
		if previous := countries[address]; previous == "" || previous == country {
			countries[address] = country
		} else {
			countries[address] = "?"
		}
	}
	return probes, ips, countries, nil
}

func addressProbes(ctx context.Context, c config, adapter string, ipv6 bool, system bool) []probe {
	pending := make([]provider, 0, len(providers)+len(c.Sources))
	for _, p := range providers {
		if !slices.Contains(c.DisabledSources, p.name) {
			pending = append(pending, p)
		}
	}
	for _, source := range c.Sources {
		if p, err := source.provider(); err == nil {
			pending = append(pending, p)
		}
	}
	pending = slices.DeleteFunc(pending, func(p provider) bool { return p.v6 && !ipv6 })
	type outcome struct {
		index int
		probe
	}
	results := make(chan outcome, len(pending))
	for index, p := range pending {
		go func() {
			endpoint, _ := url.Parse(p.url)
			item := probe{Name: p.name, host: strings.TrimSuffix(strings.ToLower(endpoint.Hostname()), "."), ipv6: p.v6}
			var proxy *url.URL
			var err error
			if system {
				proxy, err = resolveSystemProxy(ctx, endpoint)
			}
			if err == nil {
				var ip netip.Addr
				ip, err = queryVia(ctx, p, adapter, proxy)
				if err == nil {
					item.IP = ip.String()
					item.usedProxy = proxy != nil
				}
			}
			if err != nil {
				item.Err = "provider unavailable"
			}
			results <- outcome{index, item}
		}()
	}
	replies := make([]probe, len(pending))
	for range pending {
		item := <-results
		replies[item.index] = item.probe
	}
	return replies
}

func consensus(probes []probe, ipv6 bool) ([]string, error) {
	var addresses []string
	families := []bool{false}
	if ipv6 {
		families = append(families, true)
	}
	for _, family := range families {
		var address string
		hosts := make(map[string]bool)
		for _, p := range probes {
			if p.ipv6 != family || p.IP == "" {
				continue
			}
			if address != "" && p.IP != address {
				return nil, errors.New("IP providers disagree")
			}
			address = p.IP
			hosts[p.host] = true
		}
		if len(hosts) < 2 {
			return nil, errors.New("two independent providers must confirm each available IP family")
		}
		addresses = append(addresses, address)
	}
	return addresses, nil
}

func allowedExit(ctx context.Context, c config, adapter string, ips []string, countries map[string]string) bool {
	for _, address := range ips {
		ip := netip.MustParseAddr(address)
		if c.allows(ip) {
			continue
		}
		if len(c.Countries) == 0 {
			return false
		}
		country := countries[address]
		if country == "" && countries == nil {
			endpoint := &url.URL{Scheme: "https", Host: "api.country.is", Path: "/" + address}
			data, err := fetchHTTPS(ctx, endpoint.String(), "4", adapter, nil, 1024)
			var geo struct{ IP, Country string }
			if err == nil && json.Unmarshal(data, &geo) == nil && geo.IP == address {
				country = geo.Country
			}
		}
		if !slices.Contains(c.Countries, country) {
			return false
		}
	}
	return len(ips) != 0
}

func networkAllows(c config, fingerprint string, ips []string) bool {
	current := append([]string(nil), ips...)
	sort.Strings(current)
	for _, network := range c.TrustedNetworks {
		if network.Fingerprint != fingerprint {
			continue
		}
		allowed := append([]string(nil), network.Addresses...)
		sort.Strings(allowed)
		if slices.Equal(current, allowed) {
			return true
		}
	}
	return false
}
