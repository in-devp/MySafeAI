//go:build !linux && !windows && !freebsd

package main

import (
	"context"
	"errors"
	"net/netip"
)

var errObserverUnsupported = errors.New("the portable monitor is unavailable on this platform")

func nativeProcessBackend() processBackend {
	return processBackend{
		func() ([]appProcess, error) { return nil, errObserverUnsupported },
		func(appProcessKey, appProcessAction) error { return errObserverUnsupported },
	}
}

func acquireWatchLock(string) (func(), error)                 { return nil, errObserverUnsupported }
func systemNameServers(context.Context) ([]netip.Addr, error) { return nil, errObserverUnsupported }
func localNetworkIdentity(context.Context) (string, string, error) {
	return "", "", errObserverUnsupported
}
