//go:build freebsd && cgo

package main

import (
	"bytes"
	"context"
	"fmt"
	"image/color"
	"image/png"
	"os"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/introspect"
	"github.com/godbus/dbus/v5/prop"
)

const itemInterface = "org.kde.StatusNotifierItem"
const itemPath = "/StatusNotifierItem"

type trayPixmap struct {
	Width, Height int32
	Pixels        []byte
}

type freeBSDTray struct {
	conn    *dbus.Conn
	name    string
	watcher string
	show    func()
}

func (t *freeBSDTray) Activate(_, _ int32) *dbus.Error {
	t.show()
	return nil
}

func (t *freeBSDTray) SecondaryActivate(x, y int32) *dbus.Error { return t.Activate(x, y) }
func (t *freeBSDTray) ContextMenu(x, y int32) *dbus.Error       { return t.Activate(x, y) }
func (t *freeBSDTray) Scroll(_ int32, _ string) *dbus.Error     { return nil }

func openFreeBSDTray(icon []byte, show func()) (*freeBSDTray, error) {
	img, err := png.Decode(bytes.NewReader(icon))
	if err != nil {
		return nil, err
	}
	bounds := img.Bounds()
	pixmap := trayPixmap{Width: int32(bounds.Dx()), Height: int32(bounds.Dy()),
		Pixels: make([]byte, 0, 4*bounds.Dx()*bounds.Dy())}
	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			pixel := color.NRGBAModel.Convert(img.At(x, y)).(color.NRGBA)
			pixmap.Pixels = append(pixmap.Pixels, pixel.A, pixel.R, pixel.G, pixel.B)
		}
	}

	conn, err := dbus.ConnectSessionBus()
	if err != nil {
		return nil, err
	}
	t := &freeBSDTray{conn: conn, name: fmt.Sprintf("%s-%d-1", itemInterface, os.Getpid()), show: show}
	if err := t.export(pixmap); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return t, nil
}

func (t *freeBSDTray) export(pixmap trayPixmap) error {
	if err := t.conn.Export(t, itemPath, itemInterface); err != nil {
		return err
	}
	properties, err := prop.Export(t.conn, itemPath, prop.Map{itemInterface: {
		"Category":   {Value: "ApplicationStatus"},
		"Id":         {Value: "app.mysafeai.desktop"},
		"Title":      {Value: "MySafeAI"},
		"Status":     {Value: "Active"},
		"IconName":   {Value: ""},
		"IconPixmap": {Value: []trayPixmap{pixmap}},
		"ItemIsMenu": {Value: false},
		"Menu":       {Value: dbus.ObjectPath("/")},
		"WindowId":   {Value: uint32(0)},
	}})
	if err != nil {
		return err
	}
	node := introspect.Node{Name: itemPath, Interfaces: []introspect.Interface{
		prop.IntrospectData,
		{Name: itemInterface, Methods: introspect.Methods(t), Properties: properties.Introspection(itemInterface)},
	}}
	if err := t.conn.Export(introspect.NewIntrospectable(&node), itemPath, "org.freedesktop.DBus.Introspectable"); err != nil {
		return err
	}
	reply, err := t.conn.RequestName(t.name, dbus.NameFlagDoNotQueue)
	if err == nil && reply != dbus.RequestNameReplyPrimaryOwner {
		return fmt.Errorf("tray name is already owned: %s", t.name)
	}
	return err
}

func (t *freeBSDTray) refresh() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	var owner string
	if err := t.conn.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.GetNameOwner", 0, watcherName).Store(&owner); err != nil {
		t.watcher = ""
		return false
	}
	if owner != t.watcher {
		watcher := t.conn.Object(owner, watcherPath)
		if err := watcher.CallWithContext(ctx, watcherName+".RegisterStatusNotifierItem", 0, t.name).Err; err != nil {
			return false
		}
		t.watcher = owner
	}
	return trayHostAvailable(t.conn, owner)
}
