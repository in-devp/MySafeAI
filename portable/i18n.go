package main

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

type languagePreference struct {
	Language string `json:"language"`
	Resolved string `json:"resolved"`
}

func (p languagePreference) valid() bool {
	return (p.Language == "system" || p.Language == "ru" || p.Language == "en") &&
		(p.Resolved == "ru" || p.Resolved == "en") && (p.Language == "system" || p.Language == p.Resolved)
}

func systemLanguage() string {
	for _, key := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		if value := strings.ToLower(os.Getenv(key)); value != "" {
			if value == "ru" || strings.HasPrefix(value, "ru_") || strings.HasPrefix(value, "ru-") {
				return "ru"
			}
			return "en"
		}
	}
	return "en"
}

func (s storage) loadLanguage() languagePreference {
	var preference languagePreference
	if s.readJSON("language.json", &preference) == nil && preference.valid() {
		return preference
	}
	return languagePreference{Language: "system", Resolved: systemLanguage()}
}

// Native menus read the preference when being created, notifications on display.
// The webview resolves its OS language and persists it for the background worker.
func userLanguage() string {
	directory, err := os.UserConfigDir()
	if err != nil {
		return systemLanguage()
	}
	return (storage{filepath.Join(directory, "MySafeAI")}).loadLanguage().Resolved
}

func nativeText(russian, english string) string {
	if userLanguage() == "ru" {
		return russian
	}
	return english
}

func (p *panel) serveLanguage(w http.ResponseWriter, r *http.Request, path string) bool {
	if r.Method != http.MethodPost || path != "api/language" {
		return false
	}
	var preference languagePreference
	if err := decode(w, r, &preference); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return true
	}
	if !preference.valid() {
		http.Error(w, "invalid language preference", http.StatusBadRequest)
		return true
	}
	p.mu.Lock()
	err := p.storage.saveJSON("language.json", preference)
	p.mu.Unlock()
	if err != nil {
		http.Error(w, "could not save language preference", http.StatusInternalServerError)
		return true
	}
	respond(w, preference)
	return true
}
