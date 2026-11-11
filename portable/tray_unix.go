//go:build linux || (freebsd && cgo)

package main

import (
	"context"
	"time"

	"github.com/godbus/dbus/v5"
)

const watcherName = "org.kde.StatusNotifierWatcher"
const watcherPath = "/StatusNotifierWatcher"

func trayAvailable() bool {
	conn, err := dbus.SessionBus()
	return err == nil && trayHostAvailable(conn, watcherName)
}

func trayHostAvailable(conn *dbus.Conn, destination string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	var available bool
	watcher := conn.Object(destination, watcherPath)
	var property dbus.Variant
	err := watcher.CallWithContext(ctx, "org.freedesktop.DBus.Properties.Get", 0,
		watcherName, "IsStatusNotifierHostRegistered").Store(&property)
	if err == nil {
		available, _ = property.Value().(bool)
	}
	return err == nil && available
}
