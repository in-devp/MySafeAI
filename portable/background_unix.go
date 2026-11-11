//go:build linux || freebsd

package main

import (
	"context"
	"errors"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/godbus/dbus/v5"
)

const startupDesktopID = "app.mysafeai.desktop"

func loginLaunchEnabled() (bool, error) {
	dir, err := autostartDirectory()
	if err != nil {
		return false, err
	}
	entry, err := os.ReadFile(filepath.Join(dir, startupDesktopID+".desktop"))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	executable, err := os.Executable()
	if err != nil {
		return false, err
	}
	command, err := desktopLaunchCommand(executable)
	if err != nil {
		return false, err
	}
	var desktop, enabled, hidden bool
	for line := range strings.Lines(string(entry)) {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") {
			desktop = line == "[Desktop Entry]"
		}
		if !desktop {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		switch strings.TrimSpace(key) {
		case "Exec":
			enabled = strings.TrimSpace(value) == command
		case "Hidden":
			hidden = hidden || strings.TrimSpace(value) == "true"
		case "X-GNOME-Autostart-enabled":
			hidden = hidden || strings.TrimSpace(value) == "false"
		}
	}
	return enabled && !hidden, nil
}

func setLoginLaunch(enabled bool) error {
	dir, err := autostartDirectory()
	if err != nil {
		return err
	}
	destination := filepath.Join(dir, startupDesktopID+".desktop")
	if !enabled {
		err := os.Remove(destination)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	command, err := desktopLaunchCommand(executable)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	file, err := os.CreateTemp(dir, ".mysafeai-autostart-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	_, writeErr := fmt.Fprintf(file, "[Desktop Entry]\nType=Application\nName=MySafeAI\nIcon=%s\nExec=%s\nTerminal=false\n", startupDesktopID, command)
	if err := errors.Join(writeErr, file.Close()); err != nil {
		return err
	}
	return os.Rename(file.Name(), destination)
}

func autostartDirectory() (string, error) {
	config, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	if !filepath.IsAbs(config) {
		return "", errors.New("login launch requires an absolute user configuration directory")
	}
	return filepath.Join(config, "autostart"), nil
}

func desktopLaunchCommand(executable string) (string, error) {
	if !filepath.IsAbs(executable) || !utf8.ValidString(executable) ||
		strings.ContainsAny(executable, "=\x00\r\n") {
		return "", errors.New("the application path cannot be registered in desktop autostart")
	}
	// Exec quoting happens after the desktop file's string escape processing.
	quote := strings.NewReplacer(`\`, `\\\\`, `"`, `\\"`, "`", "\\\\`",
		`$`, `\\$`, "%", "%%", "\t", `\t`)
	// Some launchers check argv[0] before expanding %% in Exec.
	return `/usr/bin/env -- "` + quote.Replace(executable) + `" background`, nil
}

func notifyProtection(ctx context.Context, title, body string) error {
	const service = "org.freedesktop.Notifications"
	if err := ctx.Err(); err != nil {
		return err
	}
	conn, err := dbus.SessionBus()
	if err != nil {
		return fmt.Errorf("open desktop notification session: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	server := conn.Object(service, "/org/freedesktop/Notifications")
	var capabilities []string
	if err := server.CallWithContext(ctx, service+".GetCapabilities", 0).Store(&capabilities); err != nil {
		return fmt.Errorf("read desktop notification capabilities: %w", err)
	}
	if slices.Contains(capabilities, "body-markup") {
		body = html.EscapeString(body)
	}
	hints := map[string]dbus.Variant{"desktop-entry": dbus.MakeVariant(startupDesktopID)}
	var id uint32
	if err := server.CallWithContext(ctx, service+".Notify", 0,
		"MySafeAI", uint32(0), startupDesktopID, title, body, []string{}, hints, int32(-1)).Store(&id); err != nil {
		return fmt.Errorf("deliver desktop notification: %w", err)
	}
	return nil
}
