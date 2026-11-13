package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"sort"
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
	DNSBlocked  bool     `json:"dnsBlocked,omitempty"`
}

type watchedApp struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	State string `json:"state"`
	Count int    `json:"count"`
}

type watchStatus struct {
	State            string            `json:"state"`
	Message          string            `json:"message,omitempty"`
	Apps             []watchedApp      `json:"apps"`
	Pending          []pendingApproval `json:"pending"`
	CheckedAt        time.Time         `json:"checkedAt,omitempty"`
	BrowserAllowed   bool              `json:"browserAllowed"`
	BrowserCheckedAt time.Time         `json:"browserCheckedAt,omitempty"`
	BrowserReason    string            `json:"browserReason,omitempty"`
	BrowserPolicyKey string            `json:"browserPolicyKey,omitempty"`
}

type processBackend struct {
	begin   func() func()
	list    func() ([]appProcess, error)
	signal  func(appProcessKey, appProcessAction) error
	threads func(appProcessKey) []appThreadLease
	adopt   func(appProcessKey, []appThreadLease) error
}

type policyProof struct {
	report
	checked time.Time
}

const (
	proofRefreshInterval = 5 * time.Second
	proofMaxAge          = 12 * time.Second
	localRouteInterval   = 650 * time.Millisecond
)

type proofJob struct {
	targets []string
	next    time.Time
	busy    bool
}

type routeJob struct {
	next time.Time
	busy bool
}

type watchCheckResult struct {
	generation uint64
	key        string
	targets    []string
	proof      *policyProof
	checked    map[string]time.Time
	routeOK    bool
}

// Verification jobs publish independently: a slow PAC or provider must never
// delay another application's renewed proof or the process-control loop.
// All mutable scheduler state belongs to the watcher goroutine.
type watchChecks struct {
	ctx        context.Context
	cancel     context.CancelFunc
	generation uint64
	proofs     map[string]*proofJob
	routes     map[string]*routeJob
	results    chan watchCheckResult
	verify     func(context.Context, config, string) report
	route      func(context.Context, config, connectionMode, string) (connectionPath, error)
}

type pauseRecord struct {
	Key        appProcessKey    `json:"key"`
	Targets    []string         `json:"targets"`
	Depth      int              `json:"depth"`
	Started    time.Time        `json:"started"`
	Closing    time.Time        `json:"closing,omitempty"`
	Phase      string           `json:"phase"`
	Threads    []appThreadLease `json:"threads,omitempty"`
	WasTrusted bool             `json:"wasTrusted,omitempty"`
}

type appWatch struct {
	storage     storage
	backend     processBackend
	status      atomic.Pointer[watchStatus]
	policy      config
	policyKey   string
	generation  uint64
	proofs      map[string]policyProof
	pauses      map[appProcessKey]pauseRecord
	remembered  map[appProcessKey]watchedProcess
	ranTrusted  map[appProcessKey]bool
	recoveryErr error
}

func newAppWatch(s storage, backend processBackend) *appWatch {
	w := &appWatch{storage: s, backend: backend,
		proofs: make(map[string]policyProof), pauses: make(map[appProcessKey]pauseRecord),
		remembered: make(map[appProcessKey]watchedProcess), ranTrusted: make(map[appProcessKey]bool)}
	w.status.Store(&watchStatus{State: "checking"})
	var leases []pauseRecord
	if err := s.readJSON("observer-pauses.json", &leases); err == nil {
		for _, lease := range leases {
			if lease.Key.PID <= 1 || lease.Key.Started == 0 || len(lease.Targets) == 0 {
				continue
			}
			if lease.Phase != "owned" {
				lease.Phase = "uncertain"
			} else if backend.adopt != nil {
				err := backend.adopt(lease.Key, lease.Threads)
				if errors.Is(err, os.ErrProcessDone) {
					continue
				}
				if err != nil {
					lease.Phase = "uncertain"
				}
			}
			w.pauses[lease.Key] = lease
			w.remembered[lease.Key] = watchedProcess{appProcess: appProcess{Key: lease.Key}, targets: lease.Targets, depth: lease.Depth}
			w.ranTrusted[lease.Key] = lease.WasTrusted
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

func (w *appWatch) threadLeases(key appProcessKey) []appThreadLease {
	if w.backend.threads == nil {
		return nil
	}
	return w.backend.threads(key)
}

func (w *appWatch) run(ctx context.Context) {
	tick := time.NewTicker(localRouteInterval)
	defer tick.Stop()
	events := connectionEvents(ctx)
	checks := watchChecks{results: make(chan watchCheckResult, 128), verify: verifyTarget, route: findConnectionPath}
	defer func() {
		if checks.cancel != nil {
			checks.cancel()
		}
	}()
	invalidate := func() {
		w.generation++
		w.proofs = make(map[string]policyProof)
	}
	var previousWall int64
	var previousSuspension string
	for {
		now := time.Now()
		wall := now.UnixNano()
		if previousWall != 0 && (wall-previousWall > int64(4*time.Second) || wall < previousWall) {
			invalidate()
		}
		previousWall = wall
		c, err := w.storage.load()
		key := policyFingerprint(c)
		if err != nil {
			key = "invalid"
		}
		if key != w.policyKey {
			invalidate()
			w.policyKey = key
			if err == nil {
				w.policy = c
			}
		}
		suspension := ""
		if err == nil {
			suspension = c.protectionState(now)
		}
		if suspension != previousSuspension {
			invalidate()
			if previousSuspension == "suspended" && suspension == "" &&
				c.ProtectionPausedUntil != nil && err == nil {
				w.storage.event("Пауза защиты окончена · проверяем подключение")
			}
			previousSuspension = suspension
		}
		targets := w.policy.activeTargets()
		if checks.ctx == nil || checks.generation != w.generation {
			checks.reset(ctx, w.generation, w.policy, targets)
		}
		if suspension != "" {
			status := watchStatus{State: suspension, BrowserAllowed: true,
				BrowserCheckedAt: now, BrowserReason: suspension, BrowserPolicyKey: policyFingerprint(w.policy)}
			w.releaseAll()
			if len(w.pauses) != 0 || w.recoveryErr != nil {
				status.Message = "Не удалось снять паузу с некоторых процессов."
			}
			w.status.Store(&status)
		} else if len(targets) == 0 && err == nil {
			w.releaseAll()
			w.expireProofs(now)
			status := watchStatus{State: "off"}
			w.browserStatus(&status, now, nil)
			w.status.Store(&status)
			// Turning off process observation must not turn off an enabled
			// browser extension's independent global connection verification.
			if w.policy.BrowserProtection {
				checks.scheduleProofs(w.policy, now)
				checks.scheduleRoutes(w.policy, w.proofs, now)
			}
		} else {
			w.expireProofs(now)
			w.reconcile(ctx, now, targets, err)
			if err == nil {
				checks.scheduleProofs(w.policy, now)
				checks.scheduleRoutes(w.policy, w.proofs, now)
			}
		}
	wait:
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				break wait
			case _, open := <-events:
				if !open {
					events = nil
					continue
				}
				invalidate()
				break wait
			case result := <-checks.results:
				if result.generation != w.generation {
					continue
				}
				checks.completed(result)
				if w.acceptCheck(result, time.Now()) {
					break wait
				}
			}
		}
	}
}

func policyFingerprint(c config) string {
	data, _ := json.Marshal(c)
	return fmt.Sprintf("%x", sha256.Sum256(data))
}

func (checks *watchChecks) reset(parent context.Context, generation uint64, c config, targets []appTarget) {
	if checks.cancel != nil {
		checks.cancel()
	}
	checks.ctx, checks.cancel = context.WithCancel(parent)
	checks.generation = generation
	checks.proofs = make(map[string]*proofJob)
	checks.routes = make(map[string]*routeJob)
	for _, item := range append([]appTarget{{ID: "global"}}, targets...) {
		effective, rule := c.forTarget(item.ID)
		key := item.ID
		if rule.Mode == automaticMode || rule.Mode == fullTunnel {
			effective.Rules = nil
			key = string(rule.Mode) + policyFingerprint(effective)
		}
		job := checks.proofs[key]
		if job == nil {
			job = &proofJob{}
			checks.proofs[key] = job
		}
		job.targets = append(job.targets, item.ID)
	}
}

func (checks *watchChecks) scheduleProofs(c config, now time.Time) {
	for key, job := range checks.proofs {
		if job.busy || now.Before(job.next) {
			continue
		}
		job.busy, job.next = true, now.Add(proofRefreshInterval)
		ctx, generation, targets := checks.ctx, checks.generation, job.targets
		go func() {
			r := checks.verify(ctx, c, targets[0])
			result := watchCheckResult{generation: generation, key: key, targets: targets,
				proof: &policyProof{report: r, checked: time.Now()}}
			select {
			case checks.results <- result:
			case <-ctx.Done():
			}
		}()
	}
}

func (checks *watchChecks) scheduleRoutes(c config, proofs map[string]policyProof, now time.Time) {
	groups := make(map[string]map[string]time.Time)
	for id, proof := range proofs {
		if proof.routeKey == "" {
			continue
		}
		if groups[proof.routeKey] == nil {
			groups[proof.routeKey] = make(map[string]time.Time)
		}
		groups[proof.routeKey][id] = proof.checked
	}
	for key := range checks.routes {
		if _, exists := groups[key]; !exists && !checks.routes[key].busy {
			delete(checks.routes, key)
		}
	}
	for key, checked := range groups {
		job := checks.routes[key]
		if job == nil {
			job = &routeJob{}
			checks.routes[key] = job
		}
		if job.busy || now.Before(job.next) {
			continue
		}
		var target string
		for id := range checked {
			target = id
			break
		}
		effective, rule := c.forTarget(target)
		interval, timeout := localRouteInterval, 1100*time.Millisecond
		if rule.Mode == systemProxy || rule.Mode == serviceTunnel {
			// PAC and service DNS are network operations. Do not repeat them
			// at process-scan frequency or share their deadline with other apps.
			interval, timeout = proofRefreshInterval, 5*time.Second
		}
		job.busy, job.next = true, now.Add(interval)
		generationCtx, generation := checks.ctx, checks.generation
		go func() {
			ctx, cancel := context.WithTimeout(generationCtx, timeout)
			defer cancel()
			path, err := checks.route(ctx, effective, rule.Mode, target)
			result := watchCheckResult{generation: generation, key: key, checked: checked,
				routeOK: err == nil && ctx.Err() == nil && path.key == key}
			// Deadline expiry must publish a failed check. Only cancellation
			// of this generation permits discarding the result.
			select {
			case checks.results <- result:
			case <-generationCtx.Done():
			}
		}()
	}
}

func (checks *watchChecks) completed(result watchCheckResult) {
	if result.generation != checks.generation {
		return
	}
	if result.proof != nil {
		if job := checks.proofs[result.key]; job != nil {
			job.busy = false
		}
	} else if job := checks.routes[result.key]; job != nil {
		job.busy = false
	}
}

func (w *appWatch) acceptCheck(result watchCheckResult, now time.Time) bool {
	if result.generation != w.generation {
		return false
	}
	if result.proof != nil {
		if now.Before(result.proof.checked) || now.Sub(result.proof.checked) > proofMaxAge {
			return false
		}
		for _, id := range result.targets {
			w.proofs[id] = *result.proof
		}
		return true
	}
	changed := false
	if !result.routeOK {
		for id, checked := range result.checked {
			proof, present := w.proofs[id]
			if present && proof.routeKey == result.key && proof.checked.Equal(checked) {
				delete(w.proofs, id)
				changed = true
			}
		}
	}
	return changed
}

func (w *appWatch) expireProofs(now time.Time) {
	for id, proof := range w.proofs {
		if now.Before(proof.checked) || now.Sub(proof.checked) > proofMaxAge {
			delete(w.proofs, id)
		}
	}
}

func (w *appWatch) browserStatus(status *watchStatus, now time.Time, configErr error) {
	status.BrowserAllowed = false
	status.BrowserPolicyKey = policyFingerprint(w.policy)
	proof := w.proofs["global"]
	status.BrowserCheckedAt = proof.checked
	status.BrowserReason = proof.Reason
	if configErr != nil {
		status.BrowserReason = "Не удалось прочитать правила защиты."
		return
	}
	if proof.checked.IsZero() || now.Before(proof.checked) || now.Sub(proof.checked) > proofMaxAge {
		status.BrowserReason = "Проверяем подключение."
		return
	}
	status.BrowserAllowed = proof.Trusted
}

func (w *appWatch) reconcile(ctx context.Context, now time.Time, targets []appTarget, configErr error) {
	if w.backend.begin != nil {
		defer w.backend.begin()()
	}
	status := watchStatus{State: "checking"}
	w.browserStatus(&status, now, configErr)
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
		if !lease.Started.IsZero() && !slices.Equal(lease.Targets, item.targets) && configErr == nil {
			lease.Targets = item.targets
			w.pauses[item.Key] = lease
			_ = w.savePauses()
		}
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
	if configErr == nil {
		w.releaseAllowed(active, present, &status)
	}
	for key, lease := range w.pauses {
		if !active[key] {
			continue
		}
		for _, id := range lease.Targets {
			app := byTarget[id]
			if app.State == "protected" {
				app.State = "paused"
				byTarget[id] = app
			}
		}
	}
	for _, target := range targets {
		if app, ok := byTarget[target.ID]; ok {
			status.Apps = append(status.Apps, app)
		}
	}
	w.populateApprovals(&status, targets, byTarget)
	if status.State != "failed" {
		proof := w.proofs["global"]
		if len(w.pauses) > 0 {
			status.State = "paused"
		} else if proof.Trusted {
			status.State, status.CheckedAt = "protected", proof.checked
		}
		if proof.DNSBlocked {
			status.Message = "Маршрут DNS через текущую сеть не подтверждён."
		}
	}
	if w.policy.Notifications && wasPaused != (len(w.pauses) != 0) {
		message := nativeText("Доверенное подключение восстановлено.", "Trusted connection restored.")
		if len(w.pauses) > 0 {
			message = nativeText("Приложения приостановлены до проверки подключения.", "Applications paused until the connection is verified.")
		}
		go func() { _ = notifyProtection(ctx, "MySafeAI", message) }()
	}
	w.status.Store(&status)
}

func (w *appWatch) targetsTrusted(targets []string) bool {
	return slices.IndexFunc(targets, func(id string) bool { return !w.proofs[id].Trusted }) == -1
}

func (w *appWatch) includeDetached(current []watchedProcess, processes []appProcess, targets []appTarget) []watchedProcess {
	byPID := make(map[int]appProcess, len(processes))
	for _, process := range processes {
		if process.Key.PID > 1 && process.Key.Started != 0 {
			byPID[process.Key.PID] = process
		}
	}
	active := make(map[appProcessKey]bool, len(current))
	for _, item := range current {
		active[item.Key] = true
	}
	explicitVPN := explicitVPNTargetIDs(targets)
	enabled := make(map[string]bool, len(targets))
	for _, target := range targets {
		enabled[target.ID] = true
	}
	for _, process := range processes {
		previous, known := w.remembered[process.Key]
		if !known || active[process.Key] {
			continue
		}
		// Old versions could record an IDE-inherited pause on its VPN child.
		// Do not restore that rule while the VPN boundary is recognizable.
		// Explicit matches already appear in current and are preserved above.
		behindVPN := behindInheritedProtectionBoundary(process, byPID)
		previous.appProcess = process
		previous.targets = slices.DeleteFunc(append([]string(nil), previous.targets...), func(id string) bool {
			return !enabled[id] || (behindVPN && !explicitVPN[id])
		})
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
		lease = pauseRecord{Key: item.Key, Targets: item.targets, Depth: item.depth, Started: now,
			Phase: "staging", WasTrusted: w.ranTrusted[item.Key]}
		w.pauses[item.Key] = lease
		if err := w.savePauses(); err != nil {
			delete(w.pauses, item.Key)
			status.State, status.Message = "failed", "Не удалось сохранить журнал пауз."
			return
		}
	}
	if err := w.backend.signal(item.Key, appPause); err != nil {
		if !owned {
			lease.Threads = w.threadLeases(item.Key)
			if len(lease.Threads) == 0 {
				delete(w.pauses, item.Key)
			} else {
				lease.Phase = "owned"
				w.pauses[item.Key] = lease
			}
			_ = w.savePauses()
		}
		if !errors.Is(err, os.ErrProcessDone) && !errors.Is(err, errAppProcessAlreadyStopped) {
			status.State, status.Message = "failed", "Не удалось приостановить приложение."
		}
		return
	}
	if !owned {
		lease.Phase = "owned"
		lease.Threads = w.threadLeases(item.Key)
		w.pauses[item.Key] = lease
		if err := w.savePauses(); err != nil {
			status.State, status.Message = "failed", "Не удалось подтвердить запись о паузе."
		}
		w.storage.event("На паузе · " + executableBase(item.Executable))
	} else if threads := w.threadLeases(item.Key); !slices.Equal(threads, lease.Threads) {
		lease.Threads = threads
		w.pauses[item.Key] = lease
		_ = w.savePauses()
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
			lease.Threads = w.threadLeases(lease.Key)
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
		if item.ID != "global" && active[item.ID].Count == 0 {
			continue
		}
		approval, ok := approvalFor(w.policy, item.ID, w.proofs[item.ID].report)
		if ok && !seen[approval.ID] {
			seen[approval.ID] = true
			status.Pending = append(status.Pending, approval)
		}
	}
}

func approvalFor(c config, target string, proof report) (pendingApproval, bool) {
	if c.protectionState(time.Now()) != "" || proof.Trusted || len(proof.IPs) == 0 || proof.routeKey == "" || target == "" {
		return pendingApproval{}, false
	}
	policy, rule := c.forTarget(target)
	if proof.Mode == string(directRoute) && directExitAllowed(policy, proof.IPs) {
		return pendingApproval{}, false
	}
	effectiveTarget := target
	if !rule.hasAddressPolicy() && (rule.Mode == automaticMode || rule.Mode == fullTunnel) {
		effectiveTarget = "global"
	}
	id := policyFingerprint(policy) + proof.routeKey + effectiveTarget + fmt.Sprint(proof.IPs)
	return pendingApproval{
		ID: fmt.Sprintf("%x", sha256.Sum256([]byte(id))), Target: effectiveTarget, Adapter: proof.Adapter,
		IPs: proof.IPs, Mode: proof.Mode, ProbeTarget: target, RouteKey: proof.routeKey, PolicyKey: policyFingerprint(c),
		DNSBlocked: proof.DNSBlocked,
	}, true
}
