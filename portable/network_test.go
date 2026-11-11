package main

import "testing"

func TestRequiresConsistentAndAllowedAddressesForBothFamilies(t *testing.T) {
	c := config{Adapter: "vpn", Allowed: []string{"203.0.113.0/24", "2001:db8::/48"}}
	ipv4 := []probe{{IP: "203.0.113.42"}, {IP: "203.0.113.42"}}
	ipv6 := []probe{{IP: "2001:db8::1"}, {IP: "2001:db8::1"}}
	if ips, reason := assess(c, append(ipv4, ipv6...)); reason != "" || len(ips) != 2 {
		t.Fatalf("expected two approved addresses, got %v (%s)", ips, reason)
	}
	for _, item := range []struct {
		name   string
		probes []probe
	}{
		{"missing peer", []probe{{IP: "203.0.113.42"}, {}}},
		{"different replies", []probe{{IP: "203.0.113.42"}, {IP: "203.0.113.43"}}},
		{"outside rule", []probe{{IP: "192.0.2.5"}, {IP: "192.0.2.5"}}},
		{"unconfirmed IPv6", append(ipv4, ipv6[0], probe{})},
	} {
		t.Run(item.name, func(t *testing.T) {
			if _, reason := assess(c, item.probes); reason == "" {
				t.Fatal("unexpectedly trusted")
			}
		})
	}
}
