//go:build !windows

package browserbridge

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestRegistrationInstallUpgradeAndSafeRemoval(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "helper")
	updated := filepath.Join(dir, "new-helper")
	item := registration{browser: "chrome", file: filepath.Join(dir, "browser", "NativeMessagingHosts", HostName+".json")}
	if err := registerOne(item, binary, false); err != nil {
		t.Fatal(err)
	}
	if err := registerOne(item, updated, false); err != nil {
		t.Fatal(err)
	}
	if err := registerOne(item, binary, true); err == nil {
		t.Fatal("old executable removed newer registration")
	}
	if _, err := os.Stat(item.file); err != nil {
		t.Fatal("newer registration lost")
	}
	if err := registerOne(item, updated, true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(item.file); !os.IsNotExist(err) {
		t.Fatal("registration not removed")
	}
	foreign := []byte(`{"name":"another.application","path":"/other","type":"stdio"}`)
	if err := os.WriteFile(item.file, foreign, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := registerOne(item, binary, false); err == nil {
		t.Fatal("foreign manifest replaced")
	}
	if err := registerOne(item, binary, true); err == nil {
		t.Fatal("foreign manifest removed")
	}
	data, err := os.ReadFile(item.file)
	if err != nil || string(data) != string(foreign) {
		t.Fatal("foreign registration changed")
	}
}

func TestUserInstallAndFirefoxInvocation(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "config"))
	executable := filepath.Join(dir, "mysafeai-browser-host")
	if err := os.WriteFile(executable, []byte("test executable fixture"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := Install(executable, "all"); err != nil {
		t.Fatal(err)
	}
	config, err := os.UserConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	plan, err := registrationPlan(runtime.GOOS, dir, config, "all")
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range plan {
		m, err := readManifest(item.file)
		if err != nil || !ownedManifest(m, item.browser) {
			t.Fatalf("%s: %+v %v", item.browser, m, err)
		}
		if info, err := os.Stat(item.file); err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("manifest permissions %v %v", info, err)
		}
		if item.browser == "firefox" && !ValidInvocation([]string{item.file, FirefoxID}, executable) {
			t.Fatal("registered Firefox invocation denied")
		}
	}
	if err := Uninstall(executable, "all"); err != nil {
		t.Fatal(err)
	}
	for _, item := range plan {
		if _, err := os.Stat(item.file); !os.IsNotExist(err) {
			t.Fatal("uninstall left a manifest")
		}
	}
	if err := os.Chmod(executable, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Install(executable, "chrome"); err == nil {
		t.Fatal("non-executable helper registered")
	}
}
