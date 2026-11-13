package main

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func nextWatchResult(t *testing.T, results <-chan watchCheckResult) watchCheckResult {
	t.Helper()
	select {
	case result := <-results:
		return result
	case <-time.After(3 * time.Second):
		t.Fatal("verification did not publish its independent result")
		return watchCheckResult{}
	}
}

func TestIndependentProofsPublishAndRenewWhileAnotherTargetWaits(t *testing.T) {
	var fastCalls, slowCalls atomic.Int32
	slowStarted := make(chan struct{})
	slowDone := make(chan struct{})
	checks := watchChecks{
		results: make(chan watchCheckResult, 8),
		verify: func(ctx context.Context, _ config, target string) report {
			if target == "cursor" {
				slowCalls.Add(1)
				close(slowStarted)
				defer close(slowDone)
				<-ctx.Done()
				return report{Reason: "slow service"}
			}
			fastCalls.Add(1)
			return report{Trusted: true, routeKey: "healthy-route"}
		},
	}
	c := config{Rules: map[string]appConnectionRule{"cursor": {Mode: serviceTunnel}}}
	targets := []appTarget{{ID: "codex-cli"}, {ID: "cursor"}}
	checks.reset(t.Context(), 7, c, targets)
	defer func() { checks.cancel(); <-slowDone }()
	watch := &appWatch{generation: 7, proofs: make(map[string]policyProof)}
	start := time.Now()
	for cycle := range 4 {
		// Advance only the scheduler's deadline. The slow job stays in flight
		// throughout all four renewals instead of holding a complete batch.
		checks.scheduleProofs(c, start.Add(time.Duration(cycle)*proofRefreshInterval))
		result := nextWatchResult(t, checks.results)
		if result.proof == nil || !result.proof.Trusted || len(result.targets) != 2 {
			t.Fatalf("healthy shared proof was delayed or not deduplicated: %+v", result)
		}
		checks.completed(result)
		if !watch.acceptCheck(result, time.Now()) || !watch.proofs["codex-cli"].Trusted || !watch.proofs["global"].Trusted {
			t.Fatal("healthy target could not renew while another target was checking")
		}
	}
	<-slowStarted
	if fastCalls.Load() != 4 || slowCalls.Load() != 1 {
		t.Fatalf("verification calls: fast=%d slow=%d", fastCalls.Load(), slowCalls.Load())
	}
	if _, ok := watch.proofs["cursor"]; ok {
		t.Fatal("healthy global proof was used for the unverified service policy")
	}
}

func TestRouteChecksDoNotShareDeadlineOrWaitForSlowPAC(t *testing.T) {
	type request struct {
		target  string
		timeout time.Duration
	}
	requests := make(chan request, 8)
	var slowCalls atomic.Int32
	slowDone := make(chan struct{})
	checks := watchChecks{
		results: make(chan watchCheckResult, 8),
		route: func(ctx context.Context, _ config, _ connectionMode, target string) (connectionPath, error) {
			deadline, _ := ctx.Deadline()
			requests <- request{target, time.Until(deadline)}
			if target == "cursor" {
				slowCalls.Add(1)
				defer close(slowDone)
				<-ctx.Done()
				return connectionPath{}, ctx.Err()
			}
			return connectionPath{key: "fast"}, nil
		},
	}
	c := config{Rules: map[string]appConnectionRule{"cursor": {Mode: systemProxy}}}
	checks.reset(t.Context(), 4, c, nil)
	defer func() { checks.cancel(); <-slowDone }()
	now := time.Now()
	proofs := map[string]policyProof{
		"codex-cli": {report: report{Trusted: true, routeKey: "fast"}, checked: now},
		"cursor":    {report: report{Trusted: true, routeKey: "slow"}, checked: now},
	}
	checks.scheduleRoutes(c, proofs, now)
	for range 2 {
		got := <-requests
		if got.target == "cursor" && (got.timeout < 4*time.Second || got.timeout > 5*time.Second) {
			t.Fatalf("PAC did not get its independent timeout: %s", got.timeout)
		}
		if got.target == "codex-cli" && (got.timeout < time.Second || got.timeout > 1100*time.Millisecond) {
			t.Fatalf("native route did not get its independent timeout: %s", got.timeout)
		}
	}
	watch := &appWatch{generation: 4, proofs: proofs}
	for cycle := range 2 {
		result := nextWatchResult(t, checks.results)
		if result.key != "fast" || !result.routeOK {
			t.Fatalf("healthy route was delayed or invalidated by PAC: %+v", result)
		}
		checks.completed(result)
		if watch.acceptCheck(result, time.Now()) || !watch.proofs["codex-cli"].Trusted {
			t.Fatal("successful route check changed the application's trust")
		}
		if cycle == 0 {
			checks.scheduleRoutes(c, proofs, now.Add(localRouteInterval))
		}
	}
	if slowCalls.Load() != 1 {
		t.Fatal("slow PAC was launched again before its first check completed")
	}
}

func TestRouteOwnDeadlinePublishesFailure(t *testing.T) {
	checks := watchChecks{
		results: make(chan watchCheckResult, 1),
		route: func(ctx context.Context, _ config, _ connectionMode, _ string) (connectionPath, error) {
			<-ctx.Done()
			return connectionPath{key: "route"}, nil
		},
	}
	checks.reset(t.Context(), 2, config{}, nil)
	defer checks.cancel()
	now := time.Now()
	watch := &appWatch{generation: 2, proofs: map[string]policyProof{
		"global": {report: report{Trusted: true, routeKey: "route"}, checked: now},
	}}
	checks.scheduleRoutes(config{}, watch.proofs, now)
	result := nextWatchResult(t, checks.results)
	checks.completed(result)
	if result.routeOK || !watch.acceptCheck(result, time.Now()) || len(watch.proofs) != 0 {
		t.Fatal("timed-out route check left an application trusted")
	}
	if checks.routes["route"].busy {
		t.Fatal("route timeout left the verification job stuck")
	}
}

func TestOldCheckCannotReviveInvalidatedGeneration(t *testing.T) {
	now := time.Now()
	watch := &appWatch{generation: 9, proofs: make(map[string]policyProof)}
	old := watchCheckResult{generation: 8, key: "same-key", targets: []string{"global"},
		proof: &policyProof{report: report{Trusted: true, routeKey: "old-route"}, checked: now}}
	if watch.acceptCheck(old, now) || len(watch.proofs) != 0 {
		t.Fatal("network event was undone by an old-generation result")
	}
	checks := watchChecks{generation: 9, proofs: map[string]*proofJob{"same-key": {busy: true}}}
	checks.completed(old)
	if !checks.proofs["same-key"].busy {
		t.Fatal("old completion reset the new generation's in-flight job")
	}
}

func TestDelayedRouteFailureCannotDeleteRenewedProof(t *testing.T) {
	now := time.Now()
	previous := now.Add(-time.Second)
	watch := &appWatch{generation: 3, proofs: map[string]policyProof{
		"global":    {report: report{Trusted: true, routeKey: "route"}, checked: now},
		"codex-cli": {report: report{Trusted: true, routeKey: "route"}, checked: previous},
	}}
	result := watchCheckResult{generation: 3, key: "route", checked: map[string]time.Time{
		"global": previous, "codex-cli": previous,
	}}
	if !watch.acceptCheck(result, now) {
		t.Fatal("failed route did not invalidate the proof it checked")
	}
	if !watch.proofs["global"].Trusted {
		t.Fatal("delayed failure invalidated the independently renewed proof")
	}
	if _, exists := watch.proofs["codex-cli"]; exists {
		t.Fatal("failed route retained the old matching proof")
	}
}

func TestProofExpiryDoesNotWaitForRouteChecks(t *testing.T) {
	now := time.Now()
	stale := policyProof{report: report{Trusted: true, routeKey: "route"}, checked: now.Add(-proofMaxAge - time.Nanosecond)}
	watch := &appWatch{generation: 1, proofs: map[string]policyProof{"global": stale}}
	watch.expireProofs(now)
	if len(watch.proofs) != 0 {
		t.Fatal("stale proof stayed trusted while route validation was outstanding")
	}
	result := watchCheckResult{generation: 1, targets: []string{"global"}, proof: &stale}
	if watch.acceptCheck(result, now) || len(watch.proofs) != 0 {
		t.Fatal("a result queued longer than the proof lifetime restored trust")
	}
	future := stale
	future.checked = now.Add(time.Second)
	result.proof = &future
	if watch.acceptCheck(result, now) {
		t.Fatal("future-dated proof survived a backwards wall-clock change")
	}
}

func TestResetCancelsBothKindsOfVerification(t *testing.T) {
	started := make(chan string, 2)
	cancelled := make(chan error, 2)
	checks := watchChecks{
		results: make(chan watchCheckResult, 8),
		verify: func(ctx context.Context, _ config, _ string) report {
			started <- "proof"
			<-ctx.Done()
			cancelled <- ctx.Err()
			return report{}
		},
		route: func(ctx context.Context, _ config, _ connectionMode, _ string) (connectionPath, error) {
			started <- "route"
			<-ctx.Done()
			cancelled <- ctx.Err()
			return connectionPath{}, ctx.Err()
		},
	}
	checks.reset(t.Context(), 1, config{}, nil)
	defer checks.cancel()
	now := time.Now()
	checks.scheduleProofs(config{}, now)
	checks.scheduleRoutes(config{}, map[string]policyProof{
		"global": {report: report{routeKey: "route"}, checked: now},
	}, now)
	for range 2 {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("verification did not start")
		}
	}
	checks.reset(t.Context(), 2, config{}, nil)
	for range 2 {
		select {
		case err := <-cancelled:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("old work ended without generation cancellation: %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("network reset left old verification running")
		}
	}
	for _, job := range checks.proofs {
		if job.busy || !job.next.IsZero() {
			t.Fatal("new generation is waiting for the old verification deadline")
		}
	}
}

func TestBrowserTrustUsesOnlyFreshGlobalProof(t *testing.T) {
	now := time.Now()
	watch := &appWatch{proofs: map[string]policyProof{
		"global":    {report: report{Trusted: true, Reason: "global verified"}, checked: now},
		"codex-cli": {report: report{Trusted: false}, checked: now},
	}}
	status := watchStatus{State: "paused"}
	watch.browserStatus(&status, now, nil)
	if !status.BrowserAllowed || !status.BrowserCheckedAt.Equal(now) {
		t.Fatal("an unrelated paused application blocked the verified global browser policy")
	}
	watch.browserStatus(&status, now, errors.New("invalid configuration"))
	if status.BrowserAllowed {
		t.Fatal("an unreadable policy retained previous browser trust")
	}
	watch.browserStatus(&status, now.Add(proofMaxAge+time.Nanosecond), nil)
	if status.BrowserAllowed {
		t.Fatal("expired global proof permitted browser requests")
	}
	delete(watch.proofs, "global")
	watch.proofs["codex-cli"] = policyProof{report: report{Trusted: true}, checked: now}
	watch.browserStatus(&status, now, nil)
	if status.BrowserAllowed {
		t.Fatal("an application's private allowlist authorized browser requests")
	}
}
