package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	dnsUnknown = "unknown"
	dnsTunnel  = "tunnel"
	dnsOutside = "outside"
)

type dnsRouteEntry struct {
	Address string `json:"address"`
	Adapter string `json:"adapter,omitempty"`
}

type dnsRouteReport struct {
	State   string          `json:"state"`
	Servers []dnsRouteEntry `json:"servers"`
}

func (r dnsRouteReport) fingerprint() string {
	var entries []string
	for _, server := range r.Servers {
		entries = append(entries, server.Address+"="+server.Adapter)
	}
	slices.Sort(entries)
	return strings.Join(entries, ",")
}

func dnsRoutes(ctx context.Context, adapter string) dnsRouteReport {
	result := dnsRouteReport{State: dnsUnknown}
	servers, err := systemNameServers(ctx)
	if err != nil || len(servers) == 0 {
		return result
	}
	unconfirmed := adapter == ""
	for _, server := range servers {
		entry := dnsRouteEntry{Address: server.String()}
		if server.IsLoopback() || server.IsUnspecified() || server.IsLinkLocalUnicast() {
			unconfirmed = true
		} else {
			route, err := routeFor(ctx, server)
			entry.Adapter = route
			if err != nil || route == "" {
				unconfirmed = true
			} else if adapter != "" && route != adapter {
				result.State = dnsOutside
			}
		}
		result.Servers = append(result.Servers, entry)
	}
	if result.State != dnsOutside && !unconfirmed {
		result.State = dnsTunnel
	}
	return result
}

type externalResolver struct {
	IP      string `json:"ip"`
	Name    string `json:"name,omitempty"`
	Country string `json:"country,omitempty"`
}

type dnsObservation struct {
	Status    string             `json:"status"`
	Resolvers []externalResolver `json:"resolvers,omitempty"`
}

type leakDiagnostics struct {
	Direct      []probe        `json:"direct"`
	System      []probe        `json:"system"`
	IPv4Adapter string         `json:"ipv4Adapter,omitempty"`
	IPv6Adapter string         `json:"ipv6Adapter,omitempty"`
	Proxy       string         `json:"proxy"`
	DNS         dnsRouteReport `json:"dns"`
	ExternalDNS dnsObservation `json:"externalDNS"`
}

func diagnoseLeaks(ctx context.Context, c config) leakDiagnostics {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	result := leakDiagnostics{Proxy: "unknown", ExternalDNS: dnsObservation{Status: "disabled"}}
	var wait sync.WaitGroup
	wait.Go(func() { result.Direct = addressProbes(ctx, c, "", true, false) })
	wait.Go(func() { result.System = addressProbes(ctx, c, "", false, true) })
	wait.Go(func() {
		result.IPv4Adapter, _ = routeFor(ctx, anchors4[0])
		result.IPv6Adapter, _ = routeFor(ctx, anchors6[0])
		adapter := c.Adapter
		if adapter == "" {
			adapter = automaticAdapter(ctx)
		}
		result.DNS = dnsRoutes(ctx, adapter)
	})
	if c.ObserveDNS {
		wait.Go(func() { result.ExternalDNS = observeResolvers(ctx) })
	}
	wait.Wait()
	for _, p := range result.System {
		if p.usedProxy {
			result.Proxy = "proxy"
			break
		}
		if p.IP != "" {
			result.Proxy = "direct"
		}
	}
	return result
}

func observeResolvers(ctx context.Context) dnsObservation {
	unavailable := dnsObservation{Status: "unconfirmed"}
	token, err := fetchHTTPS(ctx, "https://bash.ws/id", "", "", nil, 128)
	id := strings.TrimSpace(string(token))
	if err != nil || !validObserverID(id) {
		return unavailable
	}
	probeCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	var wait sync.WaitGroup
	for i := 1; i <= 6; i++ {
		host := fmt.Sprintf("%d.%s.bash.ws", i, id)
		family := "ip4"
		if i%2 == 0 {
			family = "ip6"
		}
		wait.Go(func() { _, _ = net.DefaultResolver.LookupNetIP(probeCtx, family, host) })
		wait.Go(func() { _, _ = fetchHTTPS(probeCtx, "https://"+host+"/", "", "", nil, 1024) })
	}
	wait.Wait()
	cancel()
	endpoint := url.URL{Scheme: "https", Host: "bash.ws", Path: "/dnsleak/test/" + id, RawQuery: "json=2"}
	for range 3 {
		timer := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return unavailable
		case <-timer.C:
		}
		readCtx, stop := context.WithTimeout(ctx, 3*time.Second)
		payload, err := fetchHTTPS(readCtx, endpoint.String(), "", "", nil, 65536)
		stop()
		if err == nil {
			resolvers, err := parseObservedResolvers(payload)
			if err == nil && len(resolvers) > 0 {
				return dnsObservation{Status: "observed", Resolvers: resolvers}
			}
		}
	}
	return unavailable
}

func validObserverID(id string) bool {
	if len(id) == 0 || len(id) > 63 {
		return false
	}
	for _, b := range []byte(id) {
		if (b < '0' || b > '9') && (b < 'a' || b > 'z') && (b < 'A' || b > 'Z') {
			return false
		}
	}
	return true
}

func parseObservedResolvers(payload []byte) ([]externalResolver, error) {
	var rows []struct {
		Type, IP, Org, ASN string
		Country            string `json:"country_name"`
	}
	if err := json.Unmarshal(payload, &rows); err != nil {
		return nil, err
	}
	var resolvers []externalResolver
	seen := make(map[netip.Addr]bool)
	for _, row := range rows {
		if row.Type == "error" {
			return nil, errors.New("DNS observer did not finish the test")
		}
		ip, err := netip.ParseAddr(row.IP)
		if row.Type != "dns" || err != nil || ip.Zone() != "" || seen[ip] {
			continue
		}
		seen[ip] = true
		name := strings.TrimSpace(row.Org)
		if name == "" {
			name = strings.TrimSpace(row.ASN)
		}
		resolvers = append(resolvers, externalResolver{ip.String(), name, row.Country})
	}
	return resolvers, nil
}
