package browserbridge

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestBrowserRegistrationPlansStayInUserDirectories(t *testing.T) {
	home := filepath.Join(t.TempDir(), "home")
	config := filepath.Join(home, "config")
	for _, platform := range []string{"darwin", "linux", "freebsd", "windows"} {
		plan, err := registrationPlan(platform, home, config, "all")
		if err != nil || len(plan) != 5 {
			t.Fatalf("%s: %v %v", platform, plan, err)
		}
		for _, item := range plan {
			if !strings.HasPrefix(item.file, home+string(filepath.Separator)) || filepath.Base(item.file) != HostName+".json" {
				t.Fatalf("outside user directory: %+v", item)
			}
			if platform == "windows" && (!strings.HasPrefix(item.registryKey, `Software\`) || !strings.HasSuffix(item.registryKey, `\NativeMessagingHosts\`+HostName)) {
				t.Fatalf("unexpected registry path %q", item.registryKey)
			}
			m := manifest(filepath.Join(home, "host"), item.browser)
			if !ownedManifest(m, item.browser) {
				t.Fatalf("invalid generated manifest %+v", m)
			}
			if item.browser == "firefox" && len(m.AllowedOrigins) != 0 || item.browser != "firefox" && len(m.AllowedExtensions) != 0 {
				t.Fatal("mixed browser allowlists")
			}
		}
	}
	if _, err := registrationPlan("linux", home, config, "../../outside"); err == nil {
		t.Fatal("accepted browser path")
	}
	if _, err := registrationPlan("other", home, config, "all"); err == nil {
		t.Fatal("accepted unsupported OS")
	}
}

func TestBraveUsesActualChromiumNativeHostLocations(t *testing.T) {
	for _, platform := range []string{"darwin", "windows"} {
		chrome, _ := registrationPlan(platform, "/home/user", "/home/user/config", "chrome")
		brave, _ := registrationPlan(platform, "/home/user", "/home/user/config", "brave")
		if chrome[0].file != brave[0].file || chrome[0].registryKey != brave[0].registryKey {
			t.Fatalf("%s: Chrome and Brave must share their native host location", platform)
		}
	}
	brave, _ := registrationPlan("linux", "/home/user", "/home/user/config", "brave")
	if brave[0].file != filepath.Join("/home/user/config", "BraveSoftware", "Brave-Browser", "NativeMessagingHosts", HostName+".json") {
		t.Fatal("Linux Brave has its own native host directory")
	}
}

func TestInvocationOnlyAcceptsExactExtension(t *testing.T) {
	for _, args := range [][]string{{ChromiumOrigin}, {strings.TrimSuffix(ChromiumOrigin, "/")}} {
		if !ValidInvocation(args, "") {
			t.Fatalf("known origin rejected: %v", args)
		}
	}
	for _, args := range [][]string{
		nil, {}, {"https://example.com"}, {ChromiumOrigin + "anything"},
		{"chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/"},
		{ChromiumOrigin, "--allow-all"}, {"/tmp/unknown.json", FirefoxID},
		{ChromiumOrigin, "--parent-window=not-a-number"}, {ChromiumOrigin, "--parent-window=-1"},
	} {
		if ValidInvocation(args, "") {
			t.Fatalf("untrusted invocation accepted: %v", args)
		}
	}
	if ValidInvocation([]string{ChromiumOrigin, "--parent-window=0"}, "") != (runtime.GOOS == "windows") {
		t.Fatal("window argument platform validation")
	}
}

func TestForeignAndBroadManifestsAreNotOwned(t *testing.T) {
	m := manifest(filepath.Join(t.TempDir(), "helper"), "chrome")
	m.AllowedOrigins = []string{"chrome-extension://*/*"}
	if ownedManifest(m, "chrome") {
		t.Fatal("wildcard owned")
	}
	m = manifest(filepath.Join(t.TempDir(), "helper"), "firefox")
	m.Name = "another.application"
	if ownedManifest(m, "firefox") {
		t.Fatal("foreign host owned")
	}
	m = manifest("relative-helper", "chrome")
	if ownedManifest(m, "chrome") {
		t.Fatal("relative executable owned")
	}
}

func TestReadManifestRejectsSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows symlinks require developer mode or administrator rights")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readManifest(link); err == nil {
		t.Fatal("symlink registration accepted")
	}
}
