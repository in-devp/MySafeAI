package main

import (
	"context"
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func connectionEvents(ctx context.Context) <-chan struct{} {
	if ctx.Err() != nil {
		return nil
	}
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return nil
	}
	groups := uint32(unix.RTMGRP_LINK | unix.RTMGRP_IPV4_IFADDR | unix.RTMGRP_IPV6_IFADDR |
		unix.RTMGRP_IPV4_ROUTE | unix.RTMGRP_IPV6_ROUTE | unix.RTMGRP_IPV4_RULE |
		1<<(unix.RTNLGRP_IPV6_RULE-1))
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: groups}); err != nil {
		_ = unix.Close(fd)
		return nil
	}
	// A route can refer to a nexthop object whose replacement leaves the route
	// entry itself unchanged. Older kernels may lack this optional group.
	_ = unix.SetsockoptInt(fd, unix.SOL_NETLINK, unix.NETLINK_ADD_MEMBERSHIP, unix.RTNLGRP_NEXTHOP)

	socket := os.NewFile(uintptr(fd), "rtnetlink")
	events := make(chan struct{}, 1)
	go func() {
		defer close(events)
		defer socket.Close()
		stop := context.AfterFunc(ctx, func() { _ = socket.Close() })
		defer stop()
		var message [65536]byte
		for {
			_, err := socket.Read(message[:])
			if err != nil && !errors.Is(err, unix.ENOBUFS) {
				return
			}
			// A receive overflow also requires a fresh check.
			select {
			case events <- struct{}{}:
			default:
			}
		}
	}()
	return events
}
