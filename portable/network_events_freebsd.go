package main

import (
	"context"
	"encoding/binary"
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func connectionEvents(ctx context.Context) <-chan struct{} {
	if ctx.Err() != nil {
		return nil
	}
	fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, unix.AF_UNSPEC)
	if err != nil {
		return nil
	}

	socket := os.NewFile(uintptr(fd), "route")
	events := make(chan struct{}, 1)
	go func() {
		defer close(events)
		defer socket.Close()
		stop := context.AfterFunc(ctx, func() { _ = socket.Close() })
		defer stop()
		var message [65536]byte
		for {
			n, err := socket.Read(message[:])
			if err != nil && !errors.Is(err, unix.ENOBUFS) {
				return
			}
			if err == nil && !isFreeBSDNetworkChange(message[:n]) {
				continue
			}
			select {
			case events <- struct{}{}:
			default:
			}
		}
	}()
	return events
}

func isFreeBSDNetworkChange(messages []byte) bool {
	for len(messages) >= 4 {
		length := int(binary.NativeEndian.Uint16(messages))
		if length < 4 || length > len(messages) {
			return false
		}
		if messages[2] == unix.RTM_VERSION {
			// RTM_GET replies and RTM_MISS reports can be caused by our own
			// checks. Counting them as changes would retrigger verification.
			switch messages[3] {
			case unix.RTM_ADD, unix.RTM_DELETE, unix.RTM_CHANGE, unix.RTM_REDIRECT,
				unix.RTM_NEWADDR, unix.RTM_DELADDR, unix.RTM_IFINFO, unix.RTM_IFANNOUNCE:
				return true
			}
		}
		messages = messages[length:]
	}
	return false
}
