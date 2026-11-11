//go:build (linux || freebsd) && cgo

package main

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
)

func TestGIOProxyRoute(t *testing.T) {
	for _, test := range []struct{ raw, scheme, host string }{
		{"direct://", "", ""},
		{"http://127.0.0.1:8080", "http", "127.0.0.1:8080"},
		{"https://[::1]:8080", "https", "[::1]:8080"},
		{"socks://proxy.example:1080", "socks5", "proxy.example:1080"},
		{"socks5h://proxy.example:1080", "socks5h", "proxy.example:1080"},
	} {
		proxy, err := parseGIOProxy(test.raw)
		if err != nil {
			t.Fatalf("parse %s: %v", test.raw, err)
		}
		if test.scheme == "" && proxy == nil {
			continue
		}
		if proxy == nil || proxy.Scheme != test.scheme || proxy.Host != test.host {
			t.Fatalf("wrong route for %s", test.raw)
		}
	}
	for _, raw := range []string{"", "ftp://proxy.example", "socks4://proxy.example", "direct://proxy.example",
		"https://user:secret@proxy.example/path", "https://proxy.example/?fallback=true"} {
		if proxy, err := parseGIOProxy(raw); proxy != nil || err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatal("unsupported GIO route was accepted or exposed credentials")
		}
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
