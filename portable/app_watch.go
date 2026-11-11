package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime"
	"slices"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

type pendingApproval struct {
	ID          string   `json:"id"`
	Target      string   `json:"target"`
	Adapter     string   `json:"adapter"`
	IPs         []string `json:"ips"`
	Mode        string   `json:"mode"`
	ProbeTarget string   `json:"probeTarget"`
	RouteKey    string   `json:"routeKey"`
	PolicyKey   string   `json:"policyKey"`
}

type watchedApp struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	State string `json:"state"`
	Count int    `json:"count"`
}

type watchStatus struct {
	State     string            `json:"state"`
	Message   string            `json:"message,omitempty"`
	Apps      []watchedApp      `json:"apps"`
	Pending   []pendingApproval `json:"pending"`
	CheckedAt time.Time         `json:"checkedAt,omitempty"`
}

type processBackend struct {
	list   func() ([]appProcess, error)
	signal func(appProcessKey, appProcessAction) error
}

type policyProof struct {
	report
	checked time.Time
}

type proofBatch struct {
	generation uint64
	proofs     map[string]policyProof
}

type pauseRecord struct {
	Key     appProcessKey `json:"key"`
	Targets []string      `json:"targets"`
	Depth   int           `json:"depth"`
	Started time.Time     `json:"started"`
	Closing time.Time     `json:"closing,omitempty"`
	Phase   string        `json:"phase"`
}

type appWatch struct {
	storage     storage
	backend     processBackend
	reveal      func()
	status      atomic.Pointer[watchStatus]
	declined    sync.Map
	policy      config
	policyKey   string
	generation  uint64
	proofs      map[string]policyProof
	pauses      map[appProcessKey]pauseRecord
	remembered  map[appProcessKey]watchedProcess
	ranTrusted  map[appProcessKey]bool
	offered     map[string]bool
	recoveryErr error
}

func newAppWatch(s storage, backend processBackend, reveal func()) *appWatch {
	w := &appWatch{storage: s, backend: backend, reveal: reveal,
		proofs: make(map[string]policyProof), pauses: make(map[appProcessKey]pauseRecord),
		remembered: make(map[appProcessKey]watchedProcess), ranTrusted: make(map[appProcessKey]bool),
		offered: make(map[string]bool)}
	w.status.Store(&watchStatus{State: "checking"})
	var leases []pauseRecord
	if err := s.readJSON("observer-pauses.json", &leases); err == nil {
		for _, lease := range leases {
			if lease.Key.PID <= 1 || lease.Key.Started == 0 || len(lease.Targets) == 0 {
				continue
			}
			if runtime.GOOS == "windows" || lease.Phase != "owned" {
				lease.Phase = "uncertain"
			}
			w.pauses[lease.Key] = lease
			w.remembered[lease.Key] = watchedProcess{appProcess: appProcess{Key: lease.Key}, targets: lease.Targets, depth: lease.Depth}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		w.recoveryErr = err
	}
	return w
}

func (w *appWatch) savePauses() error {
	if w.recoveryErr != nil {
		return w.recoveryErr
	}
	records := make([]pauseRecord, 0, len(w.pauses))
	for _, record := range w.pauses {
		records = append(records, record)
	}
	sort.Slice(records, func(i, j int) bool { return records[i].Key.PID < records[j].Key.PID })
	return w.storage.saveJSON("observer-pauses.json", records)
}

func (w *appWatch) run(ctx context.Context) {
	tick := time.NewTicker(650 * time.Millisecond)
	defer tick.Stop()
	defer w.releaseAll()
	events := connectionEvents(ctx)
	batches := make(chan proofBatch, 1)
	checking := false
	nextProof := time.Time{}
	for {
		now := time.Now()
		c, err := w.storage.load()
		key := policyFingerprint(c)
		if err != nil {
			key = "invalid"
		}
		if key != w.policyKey {
			w.generation++
			w.policyKey, w.proofs = key, make(map[string]policyProof)
			nextProof = time.Time{}
			if err == nil {
				w.policy = c
			}
		}
		targets := w.policy.activeTargets()
		if len(targets) == 0 {
			w.releaseAll()
			w.status.Store(&watchStatus{State: "off"})
		} else {
			w.validateRoutes(ctx, now)
			w.reconcile(ctx, now, targets, err)
			if err == nil && !checking && !now.Before(nextProof) {
				checking = true
				nextProof = now.Add(5 * time.Second)
				go func(generation uint64, c config, targets []appTarget) {
					batches <- proofBatch{generation, collectProofs(ctx, c, targets)}
				}(w.generation, w.policy, targets)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		case _, open := <-events:
			if !open {
				events = nil
				break
			}
			w.generation++
			w.proofs = make(map[string]policyProof)
			nextProof = time.Time{}
		case batch := <-batches:
			checking = false
			if batch.generation == w.generation {
				w.proofs = batch.proofs
			}
		}
	}
}

func policyFingerprint(c config) string {
	data, _ := json.Marshal(c)
	return fmt.Sprintf("%x", sha256.Sum256(data))
}

func collectProofs(ctx context.Context, c config, targets []appTarget) map[string]policyProof {
	keys := make(map[string]string, len(targets)+1)
	completed := make(map[string]policyProof)
	results := make(chan struct {
		key   string
		proof policyProof
	}, len(targets)+1)
	for _, item := range append([]appTarget{{ID: "global"}}, targets...) {
		effective, rule := c.forTarget(item.ID)
		key := item.ID
		if rule.Mode == fullTunnel {
			effective.Rules = nil
			key = policyFingerprint(effective)
		}
		keys[item.ID] = key
		if _, ok := completed[key]; ok {
			continue
		}
		completed[key] = policyProof{}
		go func() {
			report := verifyTarget(ctx, c, item.ID)
			results <- struct {
				key   string
				proof policyProof
			}{key, policyProof{report, time.Now()}}
		}()
	}
	for range completed {
		result := <-results
		completed[result.key] = result.proof
	}
	proofs := make(map[string]policyProof, len(keys))
	for id, key := range keys {
		proofs[id] = completed[key]
	}
	return proofs
}

func (w *appWatch) validateRoutes(ctx context.Context, now time.Time) {
	ctx, cancel := context.WithTimeout(ctx, 1100*time.Millisecond)
	defer cancel()
	valid := make(map[string]bool)
	for id, proof := range w.proofs {
		if proof.routeKey == "" {
			continue
		}
		ok, known := valid[proof.routeKey]
		if !known {
			c, rule := w.policy.forTarget(id)
			path, err := findConnectionPath(ctx, c, rule.Mode, id)
			ok = err == nil && path.key == proof.routeKey
			valid[proof.routeKey] = ok
		}
		if !ok || now.Sub(proof.checked) > 12*time.Second {
			delete(w.proofs, id)
		}
	}
}

func (w *appWatch) reconcile(ctx context.Context, now time.Time, targets []appTarget, configErr error) {
	status := watchStatus{State: "checking"}
	if configErr != nil {
		status.State, status.Message = "failed", "Не удалось прочитать правила защиты."
	} else if w.recoveryErr != nil {
		status.State, status.Message = "failed", "Не удалось прочитать журнал пауз."
	}
	processes, err := w.backend.list()
	if err != nil {
		status.State, status.Message = "failed", "Не удалось проверить запущенные приложения."
		w.status.Store(&status)
		return
	}
	current := watchedProcesses(processes, targets, os.Getpid())
	current = w.includeDetached(current, processes, targets)
	active := make(map[appProcessKey]bool, len(current))
	present := make(map[appProcessKey]bool, len(processes))
	for _, process := range processes {
		present[process.Key] = true
	}
	byTarget := make(map[string]watchedApp, len(targets))
	names := make(map[string]string, len(targets))
	for _, target := range targets {
		names[target.ID] = target.Name
	}
	wasPaused := len(w.pauses) != 0
	for _, item := range current {
		active[item.Key] = true
		lease := w.pauses[item.Key]
		allowed := configErr == nil && w.targetsTrusted(item.targets) && lease.Closing.IsZero() && lease.Phase != "uncertain"
		if allowed {
			w.ranTrusted[item.Key] = true
		} else {
			w.pause(now, item, &status)
		}
		state := "protected"
		if !allowed {
			state = "paused"
			if itemLease, owned := w.pauses[item.Key]; itemLease.Phase == "uncertain" || (!owned && !item.Stopped) {
				state = "failed"
			}
		}
		for _, id := range item.targets {
			app := byTarget[id]
			app.ID, app.Name, app.Count = id, names[id], app.Count+1
			if app.State == "" || state == "failed" || (state == "paused" && app.State == "protected") {
				app.State = state
			}
			byTarget[id] = app
		}
	}
	for _, item := range current {
		w.remembered[item.Key] = item
	}
	for key := range w.remembered {
		if !active[key] {
			delete(w.remembered, key)
			delete(w.ranTrusted, key)
		}
	}
	w.releaseAllowed(active, present, &status)
	for _, target := range targets {
		if app, ok := byTarget[target.ID]; ok {
			status.Apps = append(status.Apps, app)
		}
	}
	w.populateApprovals(&status, targets, byTarget)
	if status.State != "failed" {
		if len(w.pauses) > 0 {
			status.State = "paused"
		} else if proof := w.proofs["global"]; proof.Trusted {
			status.State, status.CheckedAt = "protected", proof.checked
		}
	}
	if w.policy.Notifications && wasPaused != (len(w.pauses) != 0) {
		message := "Доверенное подключение восстановлено."
		if len(w.pauses) > 0 {
			message = "Приложения приостановлены до проверки подключения."
		}
		go func() { _ = notifyProtection(ctx, "MySafeAI", message) }()
	}
	w.status.Store(&status)
	for _, pending := range status.Pending {
		if !w.offered[pending.ID] {
			w.offered[pending.ID] = true
			if w.reveal != nil {
				w.reveal()
			}
			break
		}
	}
}

func (w *appWatch) targetsTrusted(targets []string) bool {
	return slices.IndexFunc(targets, func(id string) bool { return !w.proofs[id].Trusted }) == -1
}

func (w *appWatch) includeDetached(current []watchedProcess, processes []appProcess, targets []appTarget) []watchedProcess {
	active := make(map[appProcessKey]bool, len(current))
	for _, item := range current {
		active[item.Key] = true
	}
	enabled := make(map[string]bool, len(targets))
	for _, target := range targets {
		enabled[target.ID] = true
	}
	for _, process := range processes {
		previous, known := w.remembered[process.Key]
		if !known || active[process.Key] {
			continue
		}
		previous.appProcess = process
		previous.targets = slices.DeleteFunc(append([]string(nil), previous.targets...), func(id string) bool { return !enabled[id] })
		if len(previous.targets) != 0 {
			current = append(current, previous)
		}
	}
	sort.SliceStable(current, func(i, j int) bool { return current[i].depth < current[j].depth })
	return current
}

func (w *appWatch) pause(now time.Time, item watchedProcess, status *watchStatus) {
	lease, owned := w.pauses[item.Key]
	if owned {
		if lease.Phase == "uncertain" {
			status.State, status.Message = "failed", "Право на паузу после аварии не подтверждено. Проверьте это приложение."
			return
		}
		lease.Targets = item.targets
		w.pauses[item.Key] = lease
		if !lease.Closing.IsZero() {
			if !now.Before(lease.Closing) {
				err := w.backend.signal(item.Key, appKill)
				if err == nil || errors.Is(err, os.ErrProcessDone) {
					delete(w.pauses, item.Key)
					_ = w.savePauses()
				} else {
					status.State, status.Message = "failed", "Не удалось завершить приложение."
				}
			}
			return
		}
		if w.policy.CloseAfterDelay && w.ranTrusted[item.Key] && now.Sub(lease.Started) >= 20*time.Second {
			_ = w.backend.signal(item.Key, appTerminate)
			lease.Closing = now.Add(5 * time.Second)
			w.pauses[item.Key] = lease
			_ = w.savePauses()
			w.storage.event("Запрошено закрытие · " + executableBase(item.Executable))
			return
		}
	} else if item.Stopped {
		return
	}
	if !owned {
		lease = pauseRecord{Key: item.Key, Targets: item.targets, Depth: item.depth, Started: now, Phase: "staging"}
		w.pauses[item.Key] = lease
		if err := w.savePauses(); err != nil {
			delete(w.pauses, item.Key)
			status.State, status.Message = "failed", "Не удалось сохранить журнал пауз."
			return
		}
	}
	if err := w.backend.signal(item.Key, appPause); err != nil {
		if !owned {
			delete(w.pauses, item.Key)
			_ = w.savePauses()
		}
		if !errors.Is(err, os.ErrProcessDone) && !errors.Is(err, errAppProcessAlreadyStopped) {
			status.State, status.Message = "failed", "Не удалось приостановить приложение."
		}
		return
	}
	if !owned {
		lease.Phase = "owned"
		w.pauses[item.Key] = lease
		if err := w.savePauses(); err != nil {
			status.State, status.Message = "failed", "Не удалось подтвердить запись о паузе."
		}
		w.storage.event("На паузе · " + executableBase(item.Executable))
	}
}

func (w *appWatch) releaseAllowed(active, present map[appProcessKey]bool, status *watchStatus) {
	var releases []pauseRecord
	changed := false
	for key, lease := range w.pauses {
		if present != nil && !present[key] {
			delete(w.pauses, key)
			changed = true
			continue
		}
		if lease.Phase == "uncertain" {
			continue
		}
		if !active[key] || (lease.Closing.IsZero() && w.targetsTrusted(lease.Targets)) {
			releases = append(releases, lease)
		}
	}
	sort.Slice(releases, func(i, j int) bool { return releases[i].Depth > releases[j].Depth })
	for _, lease := range releases {
		lease.Phase = "releasing"
		w.pauses[lease.Key] = lease
		if err := w.savePauses(); err != nil {
			lease.Phase = "owned"
			w.pauses[lease.Key] = lease
			status.State, status.Message = "failed", "Не удалось сохранить состояние паузы."
			continue
		}
		if err := w.backend.signal(lease.Key, appResume); err != nil && !errors.Is(err, os.ErrProcessDone) {
			lease.Phase = "owned"
			w.pauses[lease.Key] = lease
			changed = true
			status.State, status.Message = "failed", "Не удалось возобновить приложение."
			continue
		}
		delete(w.pauses, lease.Key)
		changed = true
		w.storage.event(fmt.Sprintf("Продолжено · PID %d", lease.Key.PID))
	}
	if changed {
		_ = w.savePauses()
	}
}

func (w *appWatch) releaseAll() {
	w.releaseAllowed(nil, nil, &watchStatus{})
}

func (w *appWatch) populateApprovals(status *watchStatus, targets []appTarget, active map[string]watchedApp) {
	seen := make(map[string]bool)
	for _, item := range append([]appTarget{{ID: "global"}}, targets...) {
		proof := w.proofs[item.ID]
		if proof.Trusted || len(proof.IPs) == 0 || proof.routeKey == "" {
			continue
		}
		if item.ID != "global" && active[item.ID].Count == 0 {
			continue
		}
		policy, rule := w.policy.forTarget(item.ID)
		target := item.ID
		if w.policy.Rules[item.ID].Allowed == nil && w.policy.Rules[item.ID].Countries == nil && rule.Mode == fullTunnel {
			target = "global"
		}
		approval := pendingApproval{Target: target, Adapter: proof.Adapter, IPs: proof.IPs, Mode: proof.Mode,
			ProbeTarget: item.ID, RouteKey: proof.routeKey, PolicyKey: w.policyKey}
		id := policyFingerprint(policy) + proof.routeKey + target + fmt.Sprint(proof.IPs)
		approval.ID = fmt.Sprintf("%x", sha256.Sum256([]byte(id)))
		_, declined := w.declined.Load(approval.ID)
		if !declined && !seen[approval.ID] {
			seen[approval.ID] = true
			status.Pending = append(status.Pending, approval)
		}
	}
}
