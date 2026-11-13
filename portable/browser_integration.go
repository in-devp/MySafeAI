package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

// This is a short-lived local capability for the browser extension, not a
// network firewall. Never renew an expired network proof with a new heartbeat.
type browserSnapshot struct {
	Protocol   int    `json:"protocol"`
	Allowed    bool   `json:"allowed"`
	State      string `json:"state"`
	UpdatedAt  int64  `json:"updatedAt"`
	ValidUntil int64  `json:"validUntil"`
}

func browserDecision(c config, configErr error, status watchStatus, now time.Time) browserSnapshot {
	result := browserSnapshot{Protocol: 1, State: "blocked", UpdatedAt: now.UnixMilli(), ValidUntil: now.Add(2500 * time.Millisecond).UnixMilli()}
	if configErr != nil || !c.BrowserProtection || status.BrowserPolicyKey != policyFingerprint(c) {
		return result
	}
	if state := c.protectionState(now); state != "" {
		result.Allowed = true
		result.State = "disabled"
		if state == "suspended" {
			result.State = "paused"
			if deadline := c.ProtectionPausedUntil.UnixMilli(); deadline < result.ValidUntil {
				result.ValidUntil = deadline
			}
		}
		return result
	}
	age := now.Sub(status.BrowserCheckedAt)
	if status.BrowserAllowed && !status.BrowserCheckedAt.IsZero() && age >= 0 && age < proofMaxAge {
		result.Allowed, result.State = true, "trusted"
		// Do not let the browser's lease outlive the underlying IP evidence.
		expires := status.BrowserCheckedAt.Add(proofMaxAge).UnixMilli()
		if expires < result.ValidUntil {
			result.ValidUntil = expires
		}
	}
	return result
}

func (s storage) publishBrowser(status watchStatus, now time.Time) {
	c, err := s.load()
	_ = s.saveJSON("browser-state.json", browserDecision(c, err, status, now))
}

func installBrowserHost(ctx context.Context) error {
	application, err := os.Executable()
	if err != nil {
		return err
	}
	name := "mysafeai-browser-host"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	helper := filepath.Join(filepath.Dir(application), name)
	if info, err := os.Stat(helper); err != nil || !info.Mode().IsRegular() {
		return errors.New("Не найден компонент браузера. Распакуйте всю новую сборку MySafeAI в одну папку.")
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, helper, "--install", "all").Run(); err != nil {
		return errors.New("Не удалось подключить браузеры. Проверьте доступ к настройкам браузера и повторите попытку.")
	}
	return nil
}

func (p *panel) serveBrowser(w http.ResponseWriter, r *http.Request, path string) bool {
	if r.Method != http.MethodPost || path != "api/browser-install" {
		return false
	}
	var request struct{}
	if !readPanelRequest(w, r, &request) {
		return true
	}
	if p.smoke {
		http.Error(w, "Установка недоступна в проверке интерфейса.", http.StatusConflict)
		return true
	}
	if err := installBrowserHost(r.Context()); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return true
	}
	c, err := p.updatePolicy(func(c *config) error { c.BrowserProtection = true; return nil })
	if err == nil {
		p.storage.event("Подключён локальный компонент защиты сайтов в браузере")
	}
	policyResponse(w, c, err)
	return true
}
