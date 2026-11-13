package browserbridge

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
)

const (
	HostName        = "app.mysafeai.browser"
	ChromiumID      = "akehebbcjgcamdjgjpmhepmgjjlldbik"
	FirefoxID       = "mysafeai@in-devp"
	ChromiumOrigin  = "chrome-extension://" + ChromiumID + "/"
	hostDescription = "MySafeAI local browser protection status"
)

var browsers = []string{"chrome", "chromium", "edge", "brave", "firefox"}

type hostManifest struct {
	Name              string   `json:"name"`
	Description       string   `json:"description"`
	Path              string   `json:"path"`
	Type              string   `json:"type"`
	AllowedOrigins    []string `json:"allowed_origins,omitempty"`
	AllowedExtensions []string `json:"allowed_extensions,omitempty"`
}

type registration struct {
	browser     string
	file        string
	registryKey string
}

func manifest(executable, browser string) hostManifest {
	m := hostManifest{Name: HostName, Description: hostDescription, Path: executable, Type: "stdio"}
	if browser == "firefox" {
		m.AllowedExtensions = []string{FirefoxID}
	} else {
		m.AllowedOrigins = []string{ChromiumOrigin}
	}
	return m
}

// Install registers the helper for the current user only. It neither installs
// an extension nor changes browser policies, proxy settings or the firewall.
func Install(executable, browser string) error {
	return register(executable, browser, false)
}

// Uninstall only removes an exact MySafeAI manifest pointing to this helper.
func Uninstall(executable, browser string) error {
	return register(executable, browser, true)
}

func register(executable, browser string, remove bool) error {
	executable, err := filepath.Abs(executable)
	if err != nil {
		return err
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		return err
	}
	if !remove && runtime.GOOS == "darwin" && strings.Contains(executable, "/AppTranslocation/") {
		return errors.New("move MySafeAI to Applications and reopen it before connecting the browser")
	}
	info, err := os.Stat(executable)
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("browser host is not a regular executable")
	}
	if runtime.GOOS != "windows" && info.Mode()&0o111 == 0 {
		return errors.New("browser host is not executable")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	config, err := os.UserConfigDir()
	if err != nil {
		return err
	}
	plan, err := registrationPlan(runtime.GOOS, home, config, browser)
	if err != nil {
		return err
	}
	var failures []error
	for _, item := range plan {
		if err := registerOne(item, executable, remove); err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", item.browser, err))
		}
	}
	return errors.Join(failures...)
}

func registrationPlan(goos, home, config, browser string) ([]registration, error) {
	selected := []string{browser}
	if browser == "all" {
		selected = browsers
	}
	for _, name := range selected {
		if !slices.Contains(browsers, name) {
			return nil, errors.New("unknown browser; choose chrome, chromium, edge, brave, firefox or all")
		}
	}
	var plan []registration
	for _, name := range selected {
		var directory, key string
		switch goos {
		case "darwin":
			// BraveMainDelegate explicitly uses Chrome's native host directory
			// on macOS (brave-core/app/brave_main_delegate.cc).
			location := map[string]string{"chrome": "Google/Chrome", "chromium": "Chromium", "edge": "Microsoft Edge", "brave": "Google/Chrome", "firefox": "Mozilla"}[name]
			directory = filepath.Join(home, "Library", "Application Support", filepath.FromSlash(location), "NativeMessagingHosts")
		case "linux", "freebsd":
			location := map[string]string{"chrome": "google-chrome", "chromium": "chromium", "edge": "microsoft-edge", "brave": "BraveSoftware/Brave-Browser"}[name]
			directory = filepath.Join(config, filepath.FromSlash(location), "NativeMessagingHosts")
			if name == "firefox" {
				directory = filepath.Join(home, ".mozilla", "native-messaging-hosts")
			}
		case "windows":
			manifestBrowser := name
			if name == "brave" {
				manifestBrowser = "chrome"
			}
			directory = filepath.Join(config, "MySafeAI", "browser-hosts", manifestBrowser)
			// Brave inherits Chromium's Chrome registry fallback, rather than
			// looking up a BraveSoftware native-host key.
			vendor := map[string]string{"chrome": `Google\Chrome`, "chromium": `Chromium`, "edge": `Microsoft\Edge`, "brave": `Google\Chrome`, "firefox": `Mozilla`}[name]
			key = `Software\` + vendor + `\NativeMessagingHosts\` + HostName
		default:
			return nil, errors.New("native browser integration is unavailable on this platform")
		}
		plan = append(plan, registration{browser: name, file: filepath.Join(directory, HostName+".json"), registryKey: key})
	}
	return plan, nil
}

func registerOne(item registration, executable string, remove bool) error {
	existing, err := readManifest(item.file)
	missing := errors.Is(err, os.ErrNotExist)
	if err != nil && !missing {
		return errors.New("cannot read existing native host registration")
	}
	if !missing && !ownedManifest(existing, item.browser) {
		return errors.New("existing native host registration does not belong to MySafeAI")
	}
	if remove {
		if missing {
			return nil
		}
		if !samePath(existing.Path, executable) {
			return errors.New("registration points to a different MySafeAI installation")
		}
		if err := removeRegistry(item); err != nil {
			return err
		}
		return os.Remove(item.file)
	}
	if err := checkRegistry(item); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(item.file), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(manifest(executable, item.browser), "", "  ")
	if err != nil {
		return err
	}
	if err := atomicWrite(item.file, append(data, '\n')); err != nil {
		return err
	}
	return writeRegistry(item)
}

func readManifest(filename string) (hostManifest, error) {
	var m hostManifest
	info, err := os.Lstat(filename)
	if err != nil {
		return m, err
	}
	if !info.Mode().IsRegular() || info.Size() > 16384 {
		return m, errors.New("invalid native host manifest")
	}
	data, err := os.ReadFile(filename)
	if err != nil {
		return m, err
	}
	if len(data) > 16384 {
		return m, errors.New("invalid native host manifest")
	}
	err = strictJSON(data, &m)
	return m, err
}

func ownedManifest(m hostManifest, browser string) bool {
	expected := manifest(m.Path, browser)
	return m.Name == expected.Name && m.Description == expected.Description && m.Type == "stdio" &&
		filepath.IsAbs(m.Path) && slices.Equal(m.AllowedOrigins, expected.AllowedOrigins) &&
		slices.Equal(m.AllowedExtensions, expected.AllowedExtensions)
}

func samePath(a, b string) bool {
	if runtime.GOOS == "windows" {
		return strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
	}
	return filepath.Clean(a) == filepath.Clean(b)
}

func atomicWrite(filename string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(filename), ".mysafeai-host-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_, writeErr := f.Write(data)
	closeErr := f.Close()
	if err := errors.Join(writeErr, closeErr); err != nil {
		return err
	}
	return os.Rename(f.Name(), filename)
}

// ValidInvocation checks the browser-supplied origin in addition to the
// manifest allowlist. This is an allowlist, not authentication against a local
// process running with the same user's privileges.
func ValidInvocation(args []string, executable string) bool {
	if len(args) == 0 {
		return false
	}
	if args[0] == ChromiumOrigin || args[0] == strings.TrimSuffix(ChromiumOrigin, "/") {
		if len(args) == 1 {
			return true
		}
		if runtime.GOOS != "windows" || len(args) != 2 {
			return false
		}
		handle, ok := strings.CutPrefix(args[1], "--parent-window=")
		if !ok || handle == "" {
			return false
		}
		_, err := strconv.ParseUint(handle, 10, 64)
		return err == nil
	}
	if len(args) != 2 || args[1] != FirefoxID || !filepath.IsAbs(args[0]) {
		return false
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return false
	}
	config, err := os.UserConfigDir()
	if err != nil {
		return false
	}
	plan, err := registrationPlan(runtime.GOOS, home, config, "firefox")
	if err != nil || len(plan) != 1 || !samePath(args[0], plan[0].file) {
		return false
	}
	m, err := readManifest(args[0])
	if err != nil || !ownedManifest(m, "firefox") {
		return false
	}
	resolved, err := filepath.EvalSymlinks(executable)
	return err == nil && samePath(m.Path, resolved)
}
