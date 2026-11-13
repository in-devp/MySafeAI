package browserbridge

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows/registry"
)

func TestWindowsRegistrationPreservesForeignValuesAndRemovesOnlyOwnDefault(t *testing.T) {
	name := fmt.Sprintf("MySafeAI-BridgeTest-%d-%d", os.Getpid(), time.Now().UnixNano())
	item := registration{browser: "chrome", file: filepath.Join(t.TempDir(), HostName+".json"), registryKey: `Software\` + name}
	t.Cleanup(func() {
		for _, view := range registryViews {
			parent, err := registry.OpenKey(registry.CURRENT_USER, `Software`, registry.ALL_ACCESS|view)
			if err == nil {
				_ = registry.DeleteKey(parent, name)
				_ = parent.Close()
			}
		}
	})
	executable := filepath.Join(t.TempDir(), "mysafeai-browser-host.exe")
	if err := registerOne(item, executable, false); err != nil {
		t.Fatal(err)
	}
	for _, view := range registryViews {
		key, err := registry.OpenKey(registry.CURRENT_USER, item.registryKey, registry.QUERY_VALUE|registry.SET_VALUE|view)
		if err != nil {
			t.Fatal(err)
		}
		value, kind, err := key.GetStringValue("")
		if err != nil || kind != registry.SZ || value != item.file {
			t.Fatalf("wrong registered value %q %d %v", value, kind, err)
		}
		if err := key.SetStringValue("unrelated-test-value", "preserve"); err != nil {
			t.Fatal(err)
		}
		_ = key.Close()
	}
	if err := registerOne(item, filepath.Join(t.TempDir(), "different.exe"), true); err == nil {
		t.Fatal("removed another executable's registration")
	}
	if err := registerOne(item, executable, true); err != nil {
		t.Fatal(err)
	}
	for _, view := range registryViews {
		key, err := registry.OpenKey(registry.CURRENT_USER, item.registryKey, registry.QUERY_VALUE|registry.SET_VALUE|view)
		if err != nil {
			t.Fatal("unrelated registry data deleted", err)
		}
		if _, _, err := key.GetStringValue(""); !errors.Is(err, registry.ErrNotExist) {
			t.Fatal("default value not removed")
		}
		if value, _, err := key.GetStringValue("unrelated-test-value"); err != nil || value != "preserve" {
			t.Fatal("unrelated value changed")
		}
		_ = key.Close()
	}
	// The views may alias under HKCU. Verify both before changing either.
	for _, view := range registryViews {
		key, err := registry.OpenKey(registry.CURRENT_USER, item.registryKey, registry.SET_VALUE|view)
		if err != nil {
			t.Fatal(err)
		}
		if err := key.SetStringValue("", filepath.Join(t.TempDir(), "foreign.json")); err != nil {
			t.Fatal(err)
		}
		_ = key.Close()
	}
	if err := registerOne(item, executable, false); err == nil {
		t.Fatal("overwrote foreign registry value")
	}
	if _, err := os.Stat(item.file); !os.IsNotExist(err) {
		t.Fatal("wrote manifest despite registry conflict")
	}
}
