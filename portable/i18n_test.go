package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestLanguagePreferenceIsIndependentOfProtectionAndWindow(t *testing.T) {
	s := storage{t.TempDir()}
	if err := s.save(config{Allowed: []string{"203.0.113.7"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.saveJSON("window.json", windowPreferences{TrayOnly: true}); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(s.dir, "portable.json"))
	p := panel{storage: s, token: "test-token"}
	req := httptest.NewRequest(http.MethodPost, "/api/language", bytes.NewBufferString(`{"language":"en","resolved":"en"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-MySafeAI-Token", p.token)
	recorder := httptest.NewRecorder()
	p.handler().ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("language update: %d %s", recorder.Code, recorder.Body.String())
	}
	if got := s.loadLanguage(); got != (languagePreference{Language: "en", Resolved: "en"}) {
		t.Fatalf("language did not persist: %+v", got)
	}
	after, _ := os.ReadFile(filepath.Join(s.dir, "portable.json"))
	if !bytes.Equal(before, after) {
		t.Fatal("language change rewrote the security policy")
	}
	if trayOnly, err := s.loadTrayOnly(); err != nil || !trayOnly {
		t.Fatal("language change reset window preferences")
	}
}

func TestLanguagePreferenceRejectsInvalidAndUnauthenticatedWrites(t *testing.T) {
	s := storage{t.TempDir()}
	initial := languagePreference{Language: "ru", Resolved: "ru"}
	if err := s.saveJSON("language.json", initial); err != nil {
		t.Fatal(err)
	}
	p := panel{storage: s, token: "test-token"}
	for _, tc := range []struct {
		body, token string
		status      int
	}{
		{`{"language":"en","resolved":"ru"}`, p.token, http.StatusBadRequest},
		{`{"language":"xx","resolved":"en"}`, p.token, http.StatusBadRequest},
		{`{"language":"system","resolved":"xx"}`, p.token, http.StatusBadRequest},
		{`{"language":"en","resolved":"en"}`, "", http.StatusForbidden},
	} {
		req := httptest.NewRequest(http.MethodPost, "/api/language", bytes.NewBufferString(tc.body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-MySafeAI-Token", tc.token)
		recorder := httptest.NewRecorder()
		p.handler().ServeHTTP(recorder, req)
		if recorder.Code != tc.status {
			t.Fatalf("%s: got %d, want %d", tc.body, recorder.Code, tc.status)
		}
		if got := s.loadLanguage(); got != initial {
			t.Fatalf("rejected update changed language: %+v", got)
		}
	}
}

func TestLanguageSystemFallbackAndInvalidStorage(t *testing.T) {
	t.Setenv("LC_ALL", "ru_RU.UTF-8")
	s := storage{t.TempDir()}
	if got := s.loadLanguage(); got != (languagePreference{Language: "system", Resolved: "ru"}) {
		t.Fatalf("system fallback: %+v", got)
	}
	if err := s.saveJSON("language.json", languagePreference{Language: "de", Resolved: "de"}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LC_ALL", "de_DE.UTF-8")
	if got := s.loadLanguage(); got != (languagePreference{Language: "system", Resolved: "en"}) {
		t.Fatalf("invalid preference fallback: %+v", got)
	}
	if err := s.saveJSON("language.json", languagePreference{Language: "ru", Resolved: "ru"}); err != nil {
		t.Fatal(err)
	}
	if got := s.loadLanguage().Resolved; got != "ru" {
		t.Fatalf("explicit language ignored: %s", got)
	}
}
