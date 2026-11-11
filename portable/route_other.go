//go:build !linux && !windows && !freebsd

package main

import (
	"context"
	"errors"
	"net/netip"
)

func routeFor(context.Context, netip.Addr) (string, error) {
	return "", errors.New("use the native macOS app")
}
