package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

const (
	watchBeaconFile  = "observer.json"
	watchCommandFile = "observer-client.json"
)

type watchBeacon struct {
	Token  string      `json:"token"`
	At     time.Time   `json:"at"`
	Status watchStatus `json:"status"`
}

type watchCommand struct {
	Token string    `json:"token"`
	At    time.Time `json:"at"`
	Quit  bool      `json:"quit,omitempty"`
}

type backgroundStartKey struct{}

func withBackgroundStart(ctx context.Context, background bool) context.Context {
	return context.WithValue(ctx, backgroundStartKey{}, background)
}

func startsInBackground(ctx context.Context) bool {
	background, _ := ctx.Value(backgroundStartKey{}).(bool)
	return background
}

func (s storage) readJSON(name string, output any) error {
	data, err := os.ReadFile(filepath.Join(s.dir, name))
	if err != nil {
		return err
	}
	return json.Unmarshal(data, output)
}

func runWatchWorker(parent context.Context, s storage) error {
	release, err := acquireWatchLock(filepath.Join(s.dir, "observer.lock"))
	if err != nil {
		return err
	}
	defer release()
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	watch := newAppWatch(s, nativeProcessBackend(), nil)
	done := make(chan struct{})
	go func() {
		defer close(done)
		watch.run(ctx)
	}()
	var cleanExit bool
	defer func() {
		cancel()
		<-done
		if cleanExit {
			watch.releaseAll()
		}
		_ = os.Remove(filepath.Join(s.dir, watchBeaconFile))
	}()
	token := secret()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	lastClient := time.Now()
	var recentRestarts []time.Time
	for {
		now := time.Now()
		var command watchCommand
		if s.readJSON(watchCommandFile, &command) == nil && command.Token == token {
			if command.Quit && now.Sub(command.At) < 10*time.Second {
				cleanExit = true
				return nil
			}
			if command.At.After(lastClient) && !command.At.After(now.Add(time.Second)) {
				lastClient = command.At
			}
		}
		recentRestarts = slices.DeleteFunc(recentRestarts, func(t time.Time) bool { return now.Sub(t) > time.Minute })
		if !lastClient.IsZero() && now.Sub(lastClient) > 8*time.Second && len(recentRestarts) < 3 &&
			(len(recentRestarts) == 0 || now.Sub(recentRestarts[len(recentRestarts)-1]) > 5*time.Second) {
			recentRestarts = append(recentRestarts, now)
			if err := spawnMySafeAI("background"); err == nil {
				s.event("Панель перезапущена после потери связи с монитором")
			}
		}
		_ = s.saveJSON(watchBeaconFile, watchBeacon{token, now, *watch.status.Load()})
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func spawnMySafeAI(argument string) error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	command := exec.Command(executable, argument)
	if err := command.Start(); err != nil {
		return err
	}
	go func() { _ = command.Wait() }()
	return nil
}

type watchClient struct {
	storage  storage
	status   atomic.Pointer[watchStatus]
	declined sync.Map
	done     chan struct{}
}

func startWatchClient(ctx context.Context, s storage, reveal func()) *watchClient {
	w := &watchClient{storage: s, done: make(chan struct{})}
	w.status.Store(&watchStatus{State: "checking"})
	go w.run(ctx, reveal)
	return w
}

func (w *watchClient) run(ctx context.Context, reveal func()) {
	defer close(w.done)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	offered := make(map[string]bool)
	var attempted time.Time
	for {
		if ctx.Err() != nil {
			return
		}
		var beacon watchBeacon
		if w.storage.readJSON(watchBeaconFile, &beacon) == nil && validBeacon(beacon) {
			_ = w.storage.saveJSON(watchCommandFile, watchCommand{Token: beacon.Token, At: time.Now()})
			w.status.Store(&beacon.Status)
			for _, candidate := range beacon.Status.Pending {
				_, declined := w.declined.Load(candidate.ID)
				if !declined && !offered[candidate.ID] {
					offered[candidate.ID] = true
					if reveal != nil {
						reveal()
					}
					break
				}
			}
		} else if time.Since(attempted) > 4*time.Second {
			attempted = time.Now()
			w.status.Store(&watchStatus{State: "checking"})
			err := spawnMySafeAI("_watch")
			if err != nil {
				w.status.Store(&watchStatus{State: "failed", Message: "Не удалось запустить фоновую защиту."})
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func validBeacon(beacon watchBeacon) bool {
	age := time.Since(beacon.At)
	return len(beacon.Token) == 48 && age >= -time.Second && age < 4*time.Second
}

func (w *watchClient) snapshot() watchStatus {
	status := *w.status.Load()
	status.Pending = slices.DeleteFunc(append([]pendingApproval(nil), status.Pending...), func(p pendingApproval) bool {
		_, declined := w.declined.Load(p.ID)
		return declined
	})
	return status
}

func (w *watchClient) stop() error {
	<-w.done
	var beacon watchBeacon
	if w.storage.readJSON(watchBeaconFile, &beacon) != nil || !validBeacon(beacon) {
		return nil
	}
	if err := w.storage.saveJSON(watchCommandFile, watchCommand{Token: beacon.Token, At: time.Now(), Quit: true}); err != nil {
		return err
	}
	for range 25 {
		var current watchBeacon
		if err := w.storage.readJSON(watchBeaconFile, &current); errors.Is(err, os.ErrNotExist) || current.Token != beacon.Token {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return errors.New("the background monitor did not shut down")
}
