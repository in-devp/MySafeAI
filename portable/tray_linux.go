package main

import (
	"context"
	"time"

	"github.com/godbus/dbus/v5"
)

func trayAvailable() bool {
	conn, err := dbus.SessionBus()
	if err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	var available bool
	watcher := conn.Object("org.kde.StatusNotifierWatcher", "/StatusNotifierWatcher")
	var property dbus.Variant
	err = watcher.CallWithContext(ctx, "org.freedesktop.DBus.Properties.Get", 0,
		"org.kde.StatusNotifierWatcher", "IsStatusNotifierHostRegistered").Store(&property)
	if err == nil {
		available, _ = property.Value().(bool)
	}
	return err == nil && available
}
