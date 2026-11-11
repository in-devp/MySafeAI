package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	gatewayIPHelper      = windows.NewLazySystemDLL("iphlpapi.dll")
	gatewayGetBestRoute2 = gatewayIPHelper.NewProc("GetBestRoute2")
	gatewayGetIPNetRow2  = gatewayIPHelper.NewProc("GetIpNetEntry2")
)

// SOCKADDR_INET is a union of SOCKADDR_IN and SOCKADDR_IN6. The IPv4
// member starts with the family, port and network-order address bytes.
type gatewaySockaddr struct {
	Family uint16
	Port   uint16
	IPv4   uint32
	_      [20]byte
}

func makeGatewaySockaddr(ip netip.Addr) gatewaySockaddr {
	bytes := ip.As4()
	return gatewaySockaddr{Family: windows.AF_INET, IPv4: binary.LittleEndian.Uint32(bytes[:])}
}

func (addr gatewaySockaddr) address() netip.Addr {
	if addr.Family != windows.AF_INET {
		return netip.Addr{}
	}
	var bytes [4]byte
	binary.LittleEndian.PutUint32(bytes[:], addr.IPv4)
	return netip.AddrFrom4(bytes)
}

type gatewayWindowsRouteRow struct {
	LUID              uint64
	Index             uint32
	Destination       gatewaySockaddr
	PrefixLength      uint8
	_                 [3]byte
	NextHop           gatewaySockaddr
	SitePrefixLength  uint8
	_                 [3]byte
	ValidLifetime     uint32
	PreferredLifetime uint32
	Metric            uint32
	Protocol          uint32
	Loopback          uint8
	Autoconfigure     uint8
	Publish           uint8
	Immortal          uint8
	Age               uint32
	Origin            uint32
}

type gatewayWindowsNeighborRow struct {
	Address      gatewaySockaddr
	Index        uint32
	LUID         uint64
	MAC          [windows.IF_MAX_PHYS_ADDRESS_LENGTH]byte
	MACLength    uint32
	State        uint32
	Flags        uint8
	_            [3]byte
	Reachability uint32
}

type windowsGateway struct {
	index uint32
	luid  uint64
	ip    netip.Addr
}

func localNetworkIdentity(ctx context.Context) (string, string, error) {
	gateway, err := matchingWindowsGateways(ctx)
	if err != nil {
		return "", "", err
	}
	row := windows.MibIfRow2{InterfaceLuid: gateway.luid}
	if err := windows.GetIfEntry2Ex(windows.MibIfEntryNormalWithoutStatistics, &row); err != nil {
		return "", "", fmt.Errorf("GetIfEntry2Ex: %w", err)
	}
	const (
		hardwareInterface = 1 << 0
		filterInterface   = 1 << 1
		notMediaConnected = 1 << 4
		endPointInterface = 1 << 7
		mediaConnected    = 1
	)
	if row.InterfaceIndex != gateway.index || row.OperStatus != windows.IfOperStatusUp ||
		row.MediaConnectState != mediaConnected || row.TunnelType != 0 ||
		row.InterfaceAndOperStatusFlags&hardwareInterface == 0 ||
		row.InterfaceAndOperStatusFlags&(filterInterface|notMediaConnected|endPointInterface) != 0 ||
		(row.Type != windows.IF_TYPE_ETHERNET_CSMACD && row.Type != windows.IF_TYPE_IEEE80211) ||
		row.InterfaceGuid == (windows.GUID{}) {
		return "", "", errors.New("IPv4 route does not use an active hardware Ethernet or Wi-Fi adapter")
	}
	iface, err := net.InterfaceByIndex(int(gateway.index))
	if err != nil {
		return "", "", err
	}
	neighbor := gatewayWindowsNeighborRow{Address: makeGatewaySockaddr(gateway.ip), LUID: gateway.luid}
	result, _, _ := gatewayGetIPNetRow2.Call(uintptr(unsafe.Pointer(&neighbor)))
	if result != 0 {
		return "", "", fmt.Errorf("GetIpNetEntry2: %w", syscall.Errno(result))
	}
	const (
		neighborProbe       = 2
		neighborReachable   = 5
		neighborUnreachable = 1 << 1
	)
	if neighbor.Address.address() != gateway.ip || neighbor.Index != gateway.index || neighbor.LUID != gateway.luid ||
		neighbor.State < neighborProbe || neighbor.State > neighborReachable ||
		neighbor.Flags&neighborUnreachable != 0 || neighbor.MACLength != 6 {
		return "", "", errors.New("IPv4 gateway neighbor is unavailable")
	}
	mac := net.HardwareAddr(neighbor.MAC[:neighbor.MACLength])
	if !validGatewayMAC(mac) {
		return "", "", errors.New("IPv4 gateway has no valid Ethernet address")
	}
	current, err := matchingWindowsGateways(ctx)
	if err != nil || current != gateway {
		return "", "", errors.New("IPv4 gateway changed during identification")
	}
	return gatewayFingerprint(row.InterfaceGuid.String(), gateway.ip, mac), iface.Name, nil
}

func matchingWindowsGateways(ctx context.Context) (windowsGateway, error) {
	var gateway windowsGateway
	for i, anchor := range anchors4 {
		current, err := lookupWindowsGateway(ctx, anchor)
		if err != nil {
			return windowsGateway{}, err
		}
		if i != 0 && gateway != current {
			return windowsGateway{}, errors.New("IPv4 routes use different gateways")
		}
		gateway = current
	}
	return gateway, nil
}

func lookupWindowsGateway(ctx context.Context, ip netip.Addr) (windowsGateway, error) {
	if err := ctx.Err(); err != nil {
		return windowsGateway{}, err
	}
	var index uint32
	if err := windows.GetBestInterfaceEx(&windows.SockaddrInet4{Addr: ip.As4()}, &index); err != nil {
		return windowsGateway{}, fmt.Errorf("GetBestInterfaceEx: %w", err)
	}
	destination := makeGatewaySockaddr(ip)
	var route gatewayWindowsRouteRow
	var source gatewaySockaddr
	result, _, _ := gatewayGetBestRoute2.Call(0, uintptr(index), 0, uintptr(unsafe.Pointer(&destination)), 0,
		uintptr(unsafe.Pointer(&route)), uintptr(unsafe.Pointer(&source)))
	if result != 0 {
		return windowsGateway{}, fmt.Errorf("GetBestRoute2: %w", syscall.Errno(result))
	}
	gateway := route.NextHop.address()
	if route.Index != index || route.LUID == 0 || route.Loopback != 0 || !gateway.Is4() || !gateway.IsGlobalUnicast() {
		return windowsGateway{}, errors.New("no IPv4 gateway on the local interface")
	}
	return windowsGateway{index: index, luid: route.LUID, ip: gateway}, nil
}
