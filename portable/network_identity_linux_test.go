package main

import (
	"net/netip"
	"testing"
)

func TestLinuxLocalRouteAndNeighbor(t *testing.T) {
	route, err := parseLinuxLocalRoute([]byte(`[{"dst":"1.1.1.1","gateway":"192.168.1.1","dev":"wlan0"}]`))
	if err != nil || route.adapter != "wlan0" || route.gateway != netip.MustParseAddr("192.168.1.1") {
		t.Fatalf("route = %+v, err = %v", route, err)
	}
	// ip neigh omits dev when the kernel dump is already filtered to one
	// interface.
	neighbor := `{"dst":"192.168.1.1","lladdr":"06:00:10:ab:cd:ef","state":["STALE"]}`
	mac, err := parseLinuxGateway([]byte("["+neighbor+"]"), route)
	if err != nil || mac.String() != "06:00:10:ab:cd:ef" {
		t.Fatalf("MAC = %v, err = %v", mac, err)
	}
	for _, fixture := range []string{
		`[]`,
		"[" + neighbor + "," + neighbor + "]",
		`[{"dst":"192.168.1.1","lladdr":"06:00:10:ab:cd:ef","dev":"eth1","state":["STALE"]}]`,
		`[{"dst":"192.168.1.1","lladdr":"06:00:10:ab:cd:ef","state":["FAILED"]}]`,
		`[{"dst":"192.168.1.1","lladdr":"06:00:10:ab:cd:ef","state":["STALE"],"proxy":null}]`,
		`[{"dst":"192.168.1.1","lladdr":"ff:ff:ff:ff:ff:ff","state":["REACHABLE"]}]`,
	} {
		if _, err := parseLinuxGateway([]byte(fixture), route); err == nil {
			t.Errorf("accepted invalid neighbor %s", fixture)
		}
	}
}
