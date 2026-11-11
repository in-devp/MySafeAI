package main

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
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
}

func servePanel(ctx context.Context, storage storage, browser bool) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer listener.Close()
	host := listener.Addr().String()
	origin := "http://" + host
	prefix := "/" + secret() + "/"
	ui := panel{storage: storage, ctx: ctx, stop: cancel, running: make(map[string]session)}
	server := &http.Server{
		ReadHeaderTimeout: 3 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      12 * time.Second,
		IdleTimeout:       20 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			path, ok := strings.CutPrefix(r.URL.Path, prefix)
			if r.Host != host || !ok {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; script-src 'self'; img-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
			w.Header().Set("Referrer-Policy", "no-referrer")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("Cache-Control", "no-store")
			if r.Method == http.MethodPost && r.Header.Get("Origin") != origin {
				http.Error(w, "invalid origin", http.StatusForbidden)
				return
			}
			ui.serve(w, r, path)
		}),
	}
	go func() {
		<-ctx.Done()
		shutdown, finish := context.WithTimeout(context.Background(), 3*time.Second)
		defer finish()
		_ = server.Shutdown(shutdown)
	}()
	url := origin + prefix
	log.Println("MySafeAI:", url)
	if browser {
		startTray(ctx, url, cancel)
		if err := openBrowser(url); err != nil {
			log.Println("Open the URL above in your browser:", err)
		}
	}
	err = server.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func openBrowser(url string) error {
	switch runtime.GOOS {
	case "windows":
		return exec.Command("rundll32.exe", "url.dll,FileProtocolHandler", url).Start()
	case "linux":
		return exec.Command("xdg-open", url).Start()
	case "darwin":
		return exec.Command("open", url).Start()
	default:
		return errors.New("open the URL manually")
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
		respond(w, map[string]any{"config": c, "adapters": names, "journal": p.storage.recent(), "running": running})
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
		if len(p.running) >= 8 {
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
		go func() {
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
