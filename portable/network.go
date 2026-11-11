package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

var noRoute = errors.New("no route")

type config struct {
	Adapter string   `json:"adapter"`
	Allowed []string `json:"allowed"`
}

func (c config) validate() error {
	if strings.TrimSpace(c.Adapter) == "" {
		return errors.New("select your VPN adapter")
	}
	for _, value := range c.Allowed {
		if _, err := netip.ParseAddr(value); err != nil {
			if _, err := netip.ParsePrefix(value); err != nil {
				return fmt.Errorf("invalid IP or CIDR: %s", value)
			}
		}
	}
	return nil
}

func (c config) allows(ip netip.Addr) bool {
	for _, value := range c.Allowed {
		if address, err := netip.ParseAddr(value); err == nil && ip == address {
			return true
		}
		if prefix, err := netip.ParsePrefix(value); err == nil && prefix.Contains(ip) {
			return true
		}
	}
	return false
}

type probe struct {
	Name string `json:"name"`
	IP   string `json:"ip,omitempty"`
	Err  string `json:"error,omitempty"`
}

type report struct {
	Adapter string   `json:"adapter"`
	IPv6    bool     `json:"ipv6"`
	IPs     []string `json:"ips,omitempty"`
	Probes  []probe  `json:"probes,omitempty"`
	Trusted bool     `json:"trusted"`
	Reason  string   `json:"reason"`
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

func verify(ctx context.Context, c config) report {
	r := report{Adapter: c.Adapter}
	if err := c.validate(); err != nil {
		r.Reason = err.Error()
		return r
	}
	ctx, cancel := context.WithTimeout(ctx, 7*time.Second)
	defer cancel()
	ipv6, err := routes(ctx, c.Adapter)
	if err != nil {
		r.Reason = err.Error()
		return r
	}
	r.IPv6 = ipv6
	pending := providers[:2]
	if ipv6 {
		pending = providers
	}
	type outcome struct {
		index int
		probe
	}
	results := make(chan outcome, len(pending))
	r.Probes = make([]probe, len(pending))
	for index, p := range pending {
		go func() {
			item := probe{Name: p.name}
			ip, err := query(ctx, p, c.Adapter)
			if err != nil {
				item.Err = err.Error()
			} else {
				item.IP = ip.String()
			}
			results <- outcome{index, item}
		}()
	}
	for range pending {
		item := <-results
		r.Probes[item.index] = item.probe
	}
	actual6, err := routes(ctx, c.Adapter)
	if err != nil || actual6 != ipv6 {
		r.Reason = "the route changed or could not be confirmed during the check"
		return r
	}
	r.IPs, r.Reason = assess(c, r.Probes)
	r.Trusted = r.Reason == ""
	if r.Trusted {
		r.Reason = "trusted route verified"
	}
	return r
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

func query(ctx context.Context, p provider, adapter string) (netip.Addr, error) {
	family := "4"
	if p.v6 {
		family = "6"
	}
	transport := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip"+family, host)
			if err != nil {
				return nil, err
			}
			var dialer net.Dialer
			for _, ip := range ips {
				if actual, err := routeFor(ctx, ip); err != nil || actual != adapter {
					continue
				}
				conn, err := dialer.DialContext(ctx, "tcp"+family, net.JoinHostPort(ip.String(), port))
				if err != nil {
					continue
				}
				if actual, err := routeFor(ctx, ip); err == nil && actual == adapter {
					return conn, nil
				}
				conn.Close()
			}
			return nil, errors.New("could not establish a connection via the selected adapter")
		},
	}
	defer transport.CloseIdleConnections()
	client := http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, p.url, nil)
	if err != nil {
		return netip.Addr{}, err
	}
	request.Header.Set("Cache-Control", "no-cache")
	response, err := client.Do(request)
	if err != nil {
		return netip.Addr{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return netip.Addr{}, fmt.Errorf("HTTP %d", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 4097))
	if err != nil || len(data) > 4096 {
		return netip.Addr{}, errors.New("invalid provider response")
	}
	value := strings.TrimSpace(string(data))
	if p.trace {
		var addresses []string
		for line := range strings.Lines(value) {
			if ip, ok := strings.CutPrefix(strings.TrimSpace(line), "ip="); ok {
				addresses = append(addresses, ip)
			}
		}
		if len(addresses) != 1 {
			return netip.Addr{}, errors.New("invalid trace")
		}
		value = addresses[0]
	}
	ip, err := netip.ParseAddr(value)
	if err != nil || ip.Zone() != "" || ip.Is4In6() || ip.Is6() != p.v6 || !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return netip.Addr{}, errors.New("invalid public IP response")
	}
	return ip, nil
}
