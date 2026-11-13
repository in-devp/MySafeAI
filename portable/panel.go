package main

import (
	"context"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
)

//go:embed web/*
var web embed.FS

type session struct {
	Name   string   `json:"name"`
	State  runState `json:"state"`
	cancel context.CancelFunc
}

type windowPreferences struct {
	TrayOnly bool `json:"trayOnly"`
}

type panel struct {
	storage  storage
	ctx      context.Context
	stop     context.CancelFunc
	pick     func() (string, error)
	hide     func()
	tray     func() bool
	mu       sync.Mutex
	trayOnly bool
	running  map[string]session
	token    string
	smoke    bool
	closed   bool
	workers  sync.WaitGroup
	monitor  *watchClient
}

func (p *panel) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; script-src 'self'; img-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		if r.Method == http.MethodPost && subtle.ConstantTimeCompare([]byte(r.Header.Get("X-MySafeAI-Token")), []byte(p.token)) != 1 {
			http.Error(w, "invalid session", http.StatusForbidden)
			return
		}
		p.serve(w, r, strings.TrimPrefix(r.URL.Path, "/"))
	})
}

func (p *panel) shutdown() {
	p.mu.Lock()
	p.closed = true
	for _, item := range p.running {
		item.cancel()
	}
	p.mu.Unlock()
	p.workers.Wait()
	if p.monitor != nil {
		if err := p.monitor.stop(); err != nil {
			p.storage.event(err.Error())
		}
	}
}

func respond(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

func decode(w http.ResponseWriter, r *http.Request, data any) error {
	media, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if media != "application/json" {
		return errors.New("expected application/json")
	}
	input := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384))
	input.DisallowUnknownFields()
	if err := input.Decode(data); err != nil {
		return err
	}
	if err := input.Decode(new(any)); !errors.Is(err, io.EOF) {
		return errors.New("expected one JSON object")
	}
	return nil
}

func (p *panel) serve(w http.ResponseWriter, r *http.Request, path string) {
	if p.serveLanguage(w, r, path) {
		return
	}
	if p.serveBrowser(w, r, path) {
		return
	}
	if p.servePolicy(w, r, path) {
		return
	}
	switch r.Method + " " + path {
	case "GET ", "GET style.css", "GET panel.js", "GET i18n.js", "GET locales.json", "GET icon.svg":
		name := path
		if name == "" {
			name = "index.html"
		}
		data, err := web.ReadFile("web/" + name)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		contentTypes := map[string]string{
			"index.html":   "text/html; charset=utf-8",
			"panel.js":     "text/javascript; charset=utf-8",
			"i18n.js":      "text/javascript; charset=utf-8",
			"locales.json": "application/json; charset=utf-8",
			"style.css":    "text/css; charset=utf-8",
			"icon.svg":     "image/svg+xml",
		}
		w.Header().Set("Content-Type", contentTypes[name])
		_, _ = w.Write(data)
	case "GET api/state":
		c, err := p.storage.load()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		adapters, _ := net.Interfaces()
		var names []string
		for _, adapter := range adapters {
			if adapter.Flags&net.FlagLoopback == 0 {
				names = append(names, adapter.Name)
			}
		}
		sort.Strings(names)
		p.mu.Lock()
		running := make(map[string]session, len(p.running))
		for id, item := range p.running {
			running[id] = item
		}
		trayOnly := p.trayOnly
		p.mu.Unlock()
		tray := p.tray()
		var watch watchStatus
		if p.monitor != nil {
			watch = p.monitor.snapshot()
		}
		login, _ := loginLaunchEnabled()
		respond(w, map[string]any{
			"config": c, "adapters": names, "journal": p.storage.recent(), "running": running,
			"token": p.token, "smoke": p.smoke, "trayOnly": trayOnly && tray, "trayAvailable": tray, "canPick": p.pick != nil,
			"watch": watch, "targets": append(append([]appTarget(nil), builtInTargets...), c.CustomTargets...),
			"login": login, "sources": sourceNames(),
			"language": p.storage.loadLanguage(),
		})
	case "POST api/window-mode":
		var preferences windowPreferences
		if err := decode(w, r, &preferences); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if preferences.TrayOnly && !p.tray() {
			http.Error(w, "Системный трей недоступен", http.StatusConflict)
			return
		}
		p.mu.Lock()
		err := p.storage.saveJSON("window.json", preferences)
		if err == nil {
			p.trayOnly = preferences.TrayOnly
		}
		p.mu.Unlock()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		respond(w, preferences)
		if preferences.TrayOnly {
			p.hide()
		}
	case "POST api/hide":
		if !p.tray() {
			http.Error(w, "Системный трей недоступен", http.StatusConflict)
			return
		}
		respond(w, struct{}{})
		p.hide()
	case "POST api/pick":
		if p.pick == nil {
			http.Error(w, "file selection is unavailable", http.StatusServiceUnavailable)
			return
		}
		path, err := p.pick()
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		respond(w, map[string]string{"path": path})
	case "POST api/start":
		var request struct {
			Command string   `json:"command"`
			Args    []string `json:"args"`
		}
		if err := decode(w, r, &request); err != nil || strings.TrimSpace(request.Command) == "" {
			http.Error(w, "enter a program name or executable path", http.StatusBadRequest)
			return
		}
		p.mu.Lock()
		defer p.mu.Unlock()
		if p.closed || len(p.running) >= 8 {
			http.Error(w, "the panel already manages eight programs", http.StatusConflict)
			return
		}
		c, err := p.storage.load()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		id := secret()
		ctx, cancel := context.WithCancel(p.ctx)
		p.running[id] = session{Name: strings.TrimSpace(request.Command), State: runChecking, cancel: cancel}
		p.workers.Add(1)
		go func() {
			defer p.workers.Done()
			defer cancel()
			defer func() {
				p.mu.Lock()
				delete(p.running, id)
				p.mu.Unlock()
			}()
			code, err := startManaged(ctx, append([]string{strings.TrimSpace(request.Command)}, request.Args...), c, managedChecks(p.storage), streams{}, func(state runState, event string) {
				p.storage.event(event)
				p.mu.Lock()
				item := p.running[id]
				item.State = state
				p.running[id] = item
				p.mu.Unlock()
			})
			if err != nil {
				p.storage.event("launch error · " + err.Error())
			} else if code != 0 {
				p.storage.event("program stopped with a nonzero exit code")
			}
		}()
		respond(w, map[string]string{"id": id})
	case "POST api/stop":
		var request struct {
			ID string `json:"id"`
		}
		if err := decode(w, r, &request); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		p.mu.Lock()
		session, found := p.running[request.ID]
		p.mu.Unlock()
		if found {
			session.cancel()
		}
		respond(w, struct{}{})
	case "POST api/exit":
		respond(w, struct{}{})
		p.stop()
	default:
		http.NotFound(w, r)
	}
}
