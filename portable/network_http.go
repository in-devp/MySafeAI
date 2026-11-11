package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
)

func fetchHTTPS(ctx context.Context, endpoint string, family string, adapter string, proxy *url.URL, limit int64) ([]byte, error) {
	transport := &http.Transport{DisableKeepAlives: true}
	if proxy != nil {
		transport.Proxy = http.ProxyURL(proxy)
	}
	transport.DialContext = func(ctx context.Context, _, address string) (net.Conn, error) {
		var dialer net.Dialer
		if proxy != nil {
			return dialer.DialContext(ctx, "tcp", address)
		}
		if adapter == "" {
			return dialer.DialContext(ctx, "tcp"+family, address)
		}
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip"+family, host)
		if err != nil {
			return nil, err
		}
		for _, ip := range ips {
			if !usesAdapter(ctx, ip, adapter) {
				continue
			}
			conn, err := dialer.DialContext(ctx, "tcp"+family, net.JoinHostPort(ip.String(), port))
			if err != nil {
				continue
			}
			if usesAdapter(ctx, ip, adapter) {
				return conn, nil
			}
			conn.Close()
		}
		return nil, errors.New("could not connect via the selected adapter")
	}
	defer transport.CloseIdleConnections()
	client := http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	if request.URL.Scheme != "https" {
		return nil, errors.New("only HTTPS endpoints are supported")
	}
	request.Header.Set("Cache-Control", "no-cache")
	response, err := client.Do(request)
	if err != nil {
		// An HTTP proxy URL may carry credentials. Never put it in the local journal or UI.
		return nil, errors.New("HTTPS request failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, errors.New("invalid provider response")
	}
	return data, nil
}

func usesAdapter(ctx context.Context, ip netip.Addr, adapter string) bool {
	actual, err := routeFor(ctx, ip)
	return err == nil && actual == adapter
}

func queryVia(ctx context.Context, p provider, adapter string, proxy *url.URL) (netip.Addr, error) {
	family := "4"
	if p.v6 {
		family = "6"
	}
	data, err := fetchHTTPS(ctx, p.url, family, adapter, proxy, 4096)
	if err != nil {
		return netip.Addr{}, err
	}
	value := strings.TrimSpace(string(data))
	if p.trace {
		value, err = traceValue(value, "ip")
		if err != nil {
			return netip.Addr{}, err
		}
	}
	ip, err := parsePublicAddress(value)
	if err == nil && ip.Is6() != p.v6 {
		err = errors.New("unexpected address family")
	}
	return ip, err
}

func parsePublicAddress(value string) (netip.Addr, error) {
	ip, err := netip.ParseAddr(value)
	if err != nil || ip.Zone() != "" || ip.Is4In6() || !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return netip.Addr{}, errors.New("invalid public IP response")
	}
	return ip, nil
}

func traceValue(trace string, key string) (string, error) {
	var values []string
	for line := range strings.Lines(trace) {
		if value, ok := strings.CutPrefix(strings.TrimSpace(line), key+"="); ok {
			values = append(values, value)
		}
	}
	if len(values) != 1 || values[0] == "" {
		return "", fmt.Errorf("invalid trace field %s", key)
	}
	return values[0], nil
}
