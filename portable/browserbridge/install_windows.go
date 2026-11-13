package browserbridge

import (
	"errors"
	"golang.org/x/sys/windows/registry"
)

// Both views are checked before any mutation: a stale 32-bit registration must
// not shadow the current 64-bit helper. Only HKCU and this exact host are used.
var registryViews = []uint32{registry.WOW64_32KEY, registry.WOW64_64KEY}

func checkRegistry(item registration) error {
	for _, view := range registryViews {
		key, err := registry.OpenKey(registry.CURRENT_USER, item.registryKey, registry.QUERY_VALUE|view)
		if errors.Is(err, registry.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		value, kind, readErr := key.GetStringValue("")
		_ = key.Close()
		if readErr != nil && !errors.Is(readErr, registry.ErrNotExist) {
			return readErr
		}
		if readErr == nil && (kind != registry.SZ || !samePath(value, item.file)) {
			return errors.New("registry entry points to another native host manifest")
		}
	}
	return nil
}

func writeRegistry(item registration) error {
	for _, view := range registryViews {
		key, _, err := registry.CreateKey(registry.CURRENT_USER, item.registryKey, registry.SET_VALUE|view)
		if err != nil {
			return err
		}
		err = key.SetStringValue("", item.file)
		_ = key.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func removeRegistry(item registration) error {
	if err := checkRegistry(item); err != nil {
		return err
	}
	for _, view := range registryViews {
		key, err := registry.OpenKey(registry.CURRENT_USER, item.registryKey, registry.QUERY_VALUE|registry.SET_VALUE|view)
		if errors.Is(err, registry.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		// Leave the empty key and unrelated named values alone. The browser only
		// interprets the default value, and a broad key deletion is unnecessary.
		err = key.DeleteValue("")
		_ = key.Close()
		if err != nil && !errors.Is(err, registry.ErrNotExist) {
			return err
		}
	}
	return nil
}
