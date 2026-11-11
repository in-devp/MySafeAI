//go:build linux || windows || freebsd

package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"net/netip"
)

type localIPv4Route struct {
	adapter string
	gateway netip.Addr
}

func matchingLocalRoute(ctx context.Context, lookup func(context.Context, netip.Addr) (localIPv4Route, error)) (localIPv4Route, error) {
	var route localIPv4Route
	for index, anchor := range anchors4 {
		current, err := lookup(ctx, anchor)
		if err != nil {
			return localIPv4Route{}, err
		}
		if current.adapter == "" || !current.gateway.Is4() || !current.gateway.IsGlobalUnicast() {
			return localIPv4Route{}, errors.New("no IPv4 gateway on the local interface")
		}
		if index != 0 && current != route {
			return localIPv4Route{}, errors.New("IPv4 routes use different gateways")
		}
		route = current
	}
	return route, nil
}

func validGatewayMAC(mac net.HardwareAddr) bool {
	if len(mac) != 6 || mac[0]&1 != 0 {
		return false
	}
	for _, octet := range mac {
		if octet != 0 {
			return true
		}
	}
	return false
}

func gatewayFingerprint(interfaceID string, gateway netip.Addr, mac net.HardwareAddr) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(interfaceID+"\x00"+gateway.String()+"\x00"+mac.String())))
}
