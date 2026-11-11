package main

import (
	"context"
	"sync"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	networkEventAPI           = windows.NewLazySystemDLL("iphlpapi.dll")
	networkEventRegistrations = []*windows.LazyProc{
		networkEventAPI.NewProc("NotifyIpInterfaceChange"),
		networkEventAPI.NewProc("NotifyRouteChange2"),
		networkEventAPI.NewProc("NotifyUnicastIpAddressChange"),
	}
	networkEventSequence atomic.Uintptr
	networkEventTargets  sync.Map
	networkEventCallback = windows.NewCallback(deliverWindowsNetworkEvent)
)

func connectionEvents(ctx context.Context) <-chan struct{} {
	if ctx.Err() != nil {
		return nil
	}
	id := networkEventSequence.Add(1)
	signals := make(chan struct{}, 1)
	networkEventTargets.Store(id, signals)
	var handles []windows.Handle
	for _, registration := range networkEventRegistrations {
		if registration.Find() != nil {
			continue
		}
		var handle windows.Handle
		// CallerContext is opaque to Windows. Pass a numeric token so the
		// operating system never retains a Go pointer between callbacks.
		status, _, _ := registration.Call(windows.AF_UNSPEC, networkEventCallback, id, 0,
			uintptr(unsafe.Pointer(&handle)))
		if status == 0 && handle != 0 {
			handles = append(handles, handle)
		}
	}
	if len(handles) == 0 {
		networkEventTargets.Delete(id)
		return nil
	}

	events := make(chan struct{}, 1)
	go func() {
		defer close(events)
		defer func() {
			networkEventTargets.Delete(id)
			// Cancel from this goroutine, outside the native callback. An
			// in-flight callback can still enqueue into signals safely.
			for _, handle := range handles {
				_ = windows.CancelMibChangeNotify2(handle)
			}
		}()
		for {
			select {
			case <-ctx.Done():
				return
			case <-signals:
				select {
				case events <- struct{}{}:
				default:
				}
			}
		}
	}()
	return events
}

func deliverWindowsNetworkEvent(id, _, _ uintptr) uintptr {
	if target, ok := networkEventTargets.Load(id); ok {
		select {
		case target.(chan struct{}) <- struct{}{}:
		default:
		}
	}
	return 0
}
