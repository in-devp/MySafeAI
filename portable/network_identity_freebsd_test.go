package main

import (
	"net/netip"
	"testing"
)

func TestFreeBSDLocalRouteAndNeighbor(t *testing.T) {
	route, err := parseFreeBSDLocalRoute([]byte("   gateway: 192.168.1.1\n interface: em0\n flags: <UP,GATEWAY,DONE>\n"))
	if err != nil || route.adapter != "em0" || route.gateway != netip.MustParseAddr("192.168.1.1") {
		t.Fatalf("route = %+v, err = %v", route, err)
	}
	for _, flags := range []string{"UP", "UP,GATEWAY,REJECT", "UP,GATEWAY,BLACKHOLE"} {
		if _, err := parseFreeBSDLocalRoute([]byte("gateway: 192.168.1.1\ninterface: em0\nflags: <" + flags + ">")); err == nil {
			t.Errorf("accepted unusable route %s", flags)
		}
	}
	neighbor := `{"arp":{"arp-cache":[{"ip-address":"192.168.1.1","interface":"em0","mac-address":"06:00:10:ab:cd:ef","expires":"842","type":"ethernet"}]}}`
	mac, err := parseFreeBSDGateway([]byte(neighbor), route)
	if err != nil || mac.String() != "06:00:10:ab:cd:ef" {
		t.Fatalf("MAC = %v, err = %v", mac, err)
	}
	for _, fixture := range []string{
		`{"arp":{"arp-cache":[]}}`,
		`{"arp":{"arp-cache":[{"ip-address":"192.168.1.1","interface":"em0","mac-address":"06:00:10:ab:cd:ef","expired":true}]}}`,
		`{"arp":{"arp-cache":[{"ip-address":"192.168.1.1","interface":"epair0","mac-address":"06:00:10:ab:cd:ef"}]}}`,
		`{"arp":{"arp-cache":[{"ip-address":"192.168.1.1","interface":"em0","incomplete":true}]}}`,
	} {
		if _, err := parseFreeBSDGateway([]byte(fixture), route); err == nil {
			t.Errorf("accepted invalid neighbor %s", fixture)
		}
	}
}

func TestFreeBSDPhysicalDevice(t *testing.T) {
	for _, fixture := range []struct {
		output string
		device string
	}{
		{"media: Ethernet autoselect (1000baseT <full-duplex>)\nstatus: active\ndrivername: em0", "em0"},
		{"media: IEEE 802.11 Wireless Ethernet autoselect\nstatus: associated\nparent interface: iwm0\ndrivername: wlan0", "iwm0"},
		{"media: Ethernet autoselect (1000baseT <full-duplex>)\nstatus: no carrier\ndrivername: em0", ""},
		{"media: IEEE 802.11 Wireless Ethernet autoselect\nstatus: associated\ndrivername: wlan0", ""},
	} {
		device, err := freeBSDPhysicalDevice([]byte(fixture.output))
		if device != fixture.device || (err != nil) != (device == "") {
			t.Errorf("device = %q, err = %v for %q", device, err, fixture.output)
		}
	}
}
