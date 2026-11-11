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
	name   string
	cancel context.CancelFunc
}

type panel struct {
	storage storage
	ctx     context.Context
	stop    context.CancelFunc
	mu      sync.Mutex
	running map[string]session
	token   string
	smoke   bool
	closed  bool
	workers sync.WaitGroup
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
	switch r.Method + " " + path {
	case "GET ", "GET style.css", "GET panel.js", "GET icon.svg":
		name := path
		if name == "" {
			name = "index.html"
		}
		data, err := web.ReadFile("web/" + name)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", mime.TypeByExtension(name[strings.LastIndexByte(name, '.'):]))
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
		running := make(map[string]string, len(p.running))
		for id, session := range p.running {
			running[id] = session.name
		}
		p.mu.Unlock()
		respond(w, map[string]any{"config": c, "adapters": names, "journal": p.storage.recent(), "running": running, "token": p.token, "smoke": p.smoke})
	case "POST api/policy":
		var c config
		if err := decode(w, r, &c); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		p.mu.Lock()
		defer p.mu.Unlock()
		if len(p.running) != 0 {
			http.Error(w, "stop the programs launched from this panel before changing the rule", http.StatusConflict)
			return
		}
		if err := p.storage.save(c); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		respond(w, c)
	case "POST api/check":
		var c config
		if err := decode(w, r, &c); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		respond(w, verify(r.Context(), c))
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
		p.running[id] = session{strings.TrimSpace(request.Command), cancel}
		p.workers.Add(1)
		go func() {
			defer p.workers.Done()
			defer cancel()
			defer func() {
				p.mu.Lock()
				delete(p.running, id)
				p.mu.Unlock()
			}()
			code, err := startManaged(ctx, append([]string{strings.TrimSpace(request.Command)}, request.Args...), c, liveCheck, streams{}, p.storage.event)
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
