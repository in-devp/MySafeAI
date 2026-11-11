//go:build linux || freebsd

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDesktopAutostartRegistration(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	assertEnabled := func(want bool) {
		t.Helper()
		enabled, err := loginLaunchEnabled()
		if err != nil || enabled != want {
			t.Fatalf("loginLaunchEnabled() = %v, %v, want %v, nil", enabled, err, want)
		}
	}
	assertEnabled(false)
	if err := setLoginLaunch(true); err != nil {
		t.Fatal(err)
	}
	assertEnabled(true)

	entryPath := filepath.Join(dir, "autostart", startupDesktopID+".desktop")
	data, err := os.ReadFile(entryPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(entryPath, append(data, []byte("Hidden=true\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	assertEnabled(false)
	if err := setLoginLaunch(true); err != nil {
		t.Fatal(err)
	}
	assertEnabled(true)
	if err := setLoginLaunch(false); err != nil {
		t.Fatal(err)
	}
	assertEnabled(false)
	if err := setLoginLaunch(false); err != nil {
		t.Fatalf("disable is not idempotent: %v", err)
	}
}

func TestDesktopLaunchCommandEscapesPath(t *testing.T) {
	command, err := desktopLaunchCommand("/opt/MySafeAI \"quotes\" $value `command` %f \\binary\t")
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{`/usr/bin/env -- "`, `\\"quotes\\"`, `\\$value`,
		"\\\\`command\\\\`", `%%f`, `\\\\binary\t" background`} {
		if !strings.Contains(command, fragment) {
			t.Fatalf("command %q misses %q", command, fragment)
		}
	}
	for _, path := range []string{"relative", "/tmp/unsafe\nExec=/bin/false", "/tmp/invalid\x00path"} {
		if _, err := desktopLaunchCommand(path); err == nil {
			t.Fatalf("accepted invalid path %q", path)
		}
	}
}
