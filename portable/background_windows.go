package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
	"unsafe"

	"github.com/wailsapp/wails/v3/pkg/w32"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	loginRegistryPath = `Software\Microsoft\Windows\CurrentVersion\Run`
	loginRegistryName = "MySafeAI"
)

func loginLaunchEnabled() (bool, error) {
	key, err := registry.OpenKey(registry.CURRENT_USER, loginRegistryPath, registry.QUERY_VALUE)
	if errors.Is(err, registry.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer key.Close()
	command, kind, err := key.GetStringValue(loginRegistryName)
	if errors.Is(err, registry.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	args, err := windows.DecomposeCommandLine(command)
	if err != nil || kind != registry.SZ || len(args) != 2 || args[1] != "background" {
		return false, nil
	}
	executable, err := os.Executable()
	if err != nil {
		return false, err
	}
	return strings.EqualFold(filepath.Clean(executable), filepath.Clean(args[0])), nil
}

func setLoginLaunch(enabled bool) error {
	if !enabled {
		key, err := registry.OpenKey(registry.CURRENT_USER, loginRegistryPath, registry.SET_VALUE)
		if errors.Is(err, registry.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		defer key.Close()
		err = key.DeleteValue(loginRegistryName)
		if errors.Is(err, registry.ErrNotExist) {
			return nil
		}
		return err
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	command, err := registryLaunchCommand(executable)
	if err != nil {
		return err
	}
	key, _, err := registry.CreateKey(registry.CURRENT_USER, loginRegistryPath, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer key.Close()
	return key.SetStringValue(loginRegistryName, command)
}

func registryLaunchCommand(executable string) (string, error) {
	if !filepath.IsAbs(executable) || strings.ContainsAny(executable, "\"\x00\r\n") {
		return "", errors.New("the application path cannot be registered at login")
	}
	command := windows.ComposeCommandLine([]string{executable, "background"})
	if len(utf16.Encode([]rune(command))) > 260 {
		return "", errors.New("the application path is too long for Windows login launch")
	}
	return command, nil
}

type protectionNotification struct {
	ctx         context.Context
	title, body string
	result      chan error
}

var protectionNotifications = struct {
	once     sync.Once
	requests chan protectionNotification
}{requests: make(chan protectionNotification)}

func notifyProtection(ctx context.Context, title, body string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	protectionNotifications.once.Do(func() {
		go windowsNotificationLoop(protectionNotifications.requests)
	})
	request := protectionNotification{ctx, title, body, make(chan error, 1)}
	select {
	case protectionNotifications.requests <- request:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case err := <-request.result:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// A dedicated message window can deliver Shell_NotifyIcon alerts from the
// protection helper without a Wails application, installer or COM server.
func windowsNotificationLoop(requests <-chan protectionNotification) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var tray notificationTray
	defer tray.close()
	var expiry *time.Timer
	var expiryTick <-chan time.Time
	var messages *time.Ticker
	var messageTick <-chan time.Time
	for {
		select {
		case request := <-requests:
			err := request.ctx.Err()
			if err == nil {
				err = tray.show(request.title, request.body)
			}
			if err == nil {
				if expiry == nil {
					expiry = time.NewTimer(30 * time.Second)
				} else {
					expiry.Reset(30 * time.Second)
				}
				expiryTick = expiry.C
				if messages == nil {
					messages = time.NewTicker(200 * time.Millisecond)
				} else {
					messages.Reset(200 * time.Millisecond)
				}
				messageTick = messages.C
			}
			request.result <- err
		case <-expiryTick:
			tray.close()
			messages.Stop()
			expiryTick, messageTick = nil, nil
		case <-messageTick:
			var message w32.MSG
			for w32.PeekMessage(&message, tray.window, 0, 0, w32.PM_REMOVE) {
				w32.TranslateMessage(&message)
				w32.DispatchMessage(&message)
			}
		}
	}
}

type notificationTray struct {
	window w32.HWND
	icon   w32.HICON
}

func (tray *notificationTray) data() w32.NOTIFYICONDATA {
	data := w32.NOTIFYICONDATA{HWnd: tray.window, HIcon: tray.icon, UID: 1}
	data.CbSize = uint32(unsafe.Sizeof(data))
	return data
}

func (tray *notificationTray) open() error {
	class, _ := windows.UTF16PtrFromString("STATIC")
	caption, _ := windows.UTF16PtrFromString("MySafeAI")
	tray.window = w32.CreateWindowEx(0, class, caption, 0, 0, 0, 0, 0, w32.HWND_MESSAGE, 0, w32.GetApplicationHandle(), nil)
	if tray.window == 0 {
		return errors.New("create Windows notification window")
	}
	png, err := web.ReadFile("web/tray.png")
	if err == nil {
		tray.icon, err = w32.CreateSmallHIconFromImage(png)
	}
	if err != nil {
		tray.close()
		return err
	}
	data := tray.data()
	data.UFlags = w32.NIF_ICON | w32.NIF_TIP
	notificationText(data.SzTip[:], "MySafeAI")
	if !w32.ShellNotifyIcon(w32.NIM_ADD, &data) {
		tray.close()
		return errors.New("register Windows notification icon")
	}
	return nil
}

func (tray *notificationTray) show(title, body string) error {
	// Explorer may have restarted since the last notification.
	for range 2 {
		if tray.window == 0 {
			if err := tray.open(); err != nil {
				return err
			}
		}
		data := tray.data()
		data.UFlags = w32.NIF_INFO
		data.DwInfoFlags = w32.NIIF_INFO | w32.NIIF_RESPECT_QUIET_TIME
		notificationText(data.SzInfoTitle[:], title)
		notificationText(data.SzInfo[:], body)
		if w32.ShellNotifyIcon(w32.NIM_MODIFY, &data) {
			return nil
		}
		tray.close()
	}
	return errors.New("deliver Windows notification")
}

func (tray *notificationTray) close() {
	if tray.window != 0 {
		data := tray.data()
		w32.ShellNotifyIcon(w32.NIM_DELETE, &data)
		w32.DestroyWindow(tray.window)
		tray.window = 0
	}
	if tray.icon != 0 {
		w32.DestroyIcon(tray.icon)
		tray.icon = 0
	}
}

func notificationText(destination []uint16, value string) {
	if len(destination) < 2 {
		return
	}
	units := utf16.Encode([]rune(strings.ReplaceAll(value, "\x00", "")))
	if limit := len(destination) - 1; len(units) > limit {
		units = units[:limit]
		if units[len(units)-1] >= 0xd800 && units[len(units)-1] <= 0xdbff {
			units = units[:len(units)-1]
		}
	}
	copy(destination, units)
}
