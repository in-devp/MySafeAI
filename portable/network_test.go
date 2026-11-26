package main

import (
	"slices"
	"testing"
)

func TestSelectsOneIPProviderPerAvailableFamily(t *testing.T) {
	custom := []sourcePreference{
		{Name: "Custom v4", URL: "https://example.com/ip"},
		{Name: "Second v4", URL: "https://example.net/ip"},
		{Name: "Custom v6", URL: "https://ipv6.example.com/ip", IPv6: true},
	}
	for _, tc := range []struct {
		name   string
		config config
		ipv6   bool
		want   []string
	}{
		{name: "default IPv4", want: []string{"ipify"}},
		{name: "default dual stack", ipv6: true, want: []string{"ipify", "ipify IPv6"}},
		{name: "custom source takes priority", config: config{Sources: custom}, ipv6: true, want: []string{"Custom v4", "Custom v6"}},
		{name: "IPv4 only skips custom IPv6", config: config{Sources: custom}, want: []string{"Custom v4"}},
		{name: "respects disabled sources", config: config{DisabledSources: []string{"ipify", "ipify IPv6"}}, ipv6: true, want: []string{"Cloudflare", "ident.me IPv6"}},
		{name: "all built-ins disabled", config: config{DisabledSources: sourceNames()}, ipv6: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var names []string
			for _, source := range selectedAddressProviders(tc.config, tc.ipv6) {
				names = append(names, source.name)
			}
			if !slices.Equal(names, tc.want) {
				t.Fatalf("got %v, want %v", names, tc.want)
			}
		})
	}
}
