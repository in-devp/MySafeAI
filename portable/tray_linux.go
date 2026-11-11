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
	err = conn.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.NameHasOwner", 0,
		"org.kde.StatusNotifierWatcher").Store(&available)
	return err == nil && available
}
