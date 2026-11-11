package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestWindowsManualProxyDecision(t *testing.T) {
	for _, test := range []struct{ target, servers, bypass, want string }{
		{"https://api.example", "", "", ""},
		{"https://api.example", "127.0.0.1:8080", "", "http://127.0.0.1:8080"},
		{"https://api.example", "http=proxy-a:80;https=proxy-b:8080", "", "http://proxy-b:8080"},
		{"https://api.example", "proxy-a:80;https=https://proxy-b:8443", "", "https://proxy-b:8443"},
		{"https://api.example", "https=proxy-a:80;https=proxy-b:8080", "", "http://proxy-a:80"},
		{"https://api.example", "proxy-a:80", "local.example;*.example", ""},
		{"https://api.example", "proxy-a:80", "http://*.example;*.example:444", "http://proxy-a:80"},
		{"https://api.example", "proxy-a:80", "https://*.example:443", ""},
		{"https://intranet", "proxy-a:80", "<local>", ""},
		{"https://192.0.2.4", "proxy-a:80", "192.0.2.0/24", ""},
		{"https://[2001:db8::1]:443", "proxy-a:80", "[2001:db8::1]:443", ""},
	} {
		target, _ := url.Parse(test.target)
		got, err := resolveWinManualProxy(target, test.servers, test.bypass)
		if err != nil || (test.want == "" && got != nil) ||
			(test.want != "" && (got == nil || got.String() != test.want)) {
			t.Fatalf("unexpected manual result for %s using %q and bypass %q: %v", test.target, test.servers, test.bypass, err)
		}
	}
	target, _ := url.Parse("https://api.example")
	for _, servers := range []string{"http=proxy-a:80", "socks=proxy-a:1080", "https=ftp://proxy-a:80",
		"https=https://user:secret@proxy-a:80/path"} {
		if proxy, err := resolveWinManualProxy(target, servers, ""); proxy != nil || err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatal("unsupported manual route was accepted or exposed credentials")
		}
	}
}

func TestWindowsAutomaticProxyDecision(t *testing.T) {
	host, _ := windows.UTF16PtrFromString("::1")
	proxy, err := firstWinProxy(winProxyEntry{proxy: 1, scheme: winProxySchemeHTTPS, host: host, port: 8443})
	if err != nil || proxy == nil || proxy.String() != "https://[::1]:8443" {
		t.Fatalf("unexpected HTTPS proxy: %v", err)
	}
	if proxy, err := firstWinProxy(winProxyEntry{bypass: 1}); proxy != nil || err != nil {
		t.Fatalf("bypassed route: %v", err)
	}
	if proxy, err := firstWinProxy(winProxyEntry{proxy: 1, scheme: 8, host: host}); proxy != nil || err == nil {
		t.Fatal("unknown SOCKS version accepted")
	}
}

func TestSystemProxyCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	proxy, err := resolveSystemProxy(ctx, &url.URL{Scheme: "https", Host: "example.com"})
	if proxy != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled lookup: %v", err)
	}
}

func TestWindowsPACSelectsFirstRouteForEachURL(t *testing.T) {
	pac := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
		fmt.Fprint(w, `function FindProxyForURL(url, host) {
			if (host == "bypass.invalid") return "DIRECT; PROXY 192.0.2.25:8080";
			return "PROXY 192.0.2.25:8080; DIRECT";
		}`)
	}))
	defer pac.Close()
	pacURL, err := windows.UTF16PtrFromString(pac.URL + "/proxy.pac")
	if err != nil {
		t.Fatal(err)
	}
	options := winAutoProxyOptions{flags: winProxyConfigURL, autoConfigURL: pacURL}
	for _, test := range []struct{ target, want string }{
		{"https://bypass.invalid/", ""},
		{"https://proxied.invalid/", "http://192.0.2.25:8080"},
	} {
		target, err := url.Parse(test.target)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		proxy, err := resolveWinAutoProxy(ctx, target, &options)
		cancel()
		if err != nil || (test.want == "" && proxy != nil) ||
			(test.want != "" && (proxy == nil || proxy.String() != test.want)) {
			t.Fatalf("unexpected PAC route for %s: %v", test.target, err)
		}
	}
}
