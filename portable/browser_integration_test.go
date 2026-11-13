package main

import (
	"errors"
	"testing"
	"time"
)

func TestBrowserLeaseCannotOutliveNetworkProofOrPolicy(t *testing.T) {
	now := time.Now()
	c := config{BrowserProtection: true}
	status := watchStatus{State: "paused", BrowserAllowed: true, BrowserCheckedAt: now.Add(-11 * time.Second), BrowserPolicyKey: policyFingerprint(c)}
	got := browserDecision(c, nil, status, now)
	if !got.Allowed || got.State != "trusted" || got.ValidUntil != status.BrowserCheckedAt.Add(proofMaxAge).UnixMilli() {
		t.Fatalf("valid global proof must be independent of another application's pause: %+v", got)
	}
	if browserDecision(c, nil, status, now.Add(2*time.Second)).Allowed {
		t.Fatal("a fresh heartbeat renewed expired network evidence")
	}
	c.Allowed = []string{"203.0.113.10"}
	if browserDecision(c, nil, status, now).Allowed {
		t.Fatal("the old policy authorized browser traffic after a policy change")
	}
}

func TestBrowserLeaseBlocksUnavailableFutureOrDisabledIntegration(t *testing.T) {
	now := time.Now()
	c := config{BrowserProtection: true}
	status := watchStatus{BrowserAllowed: true, BrowserCheckedAt: now, BrowserPolicyKey: policyFingerprint(c)}
	if browserDecision(c, errors.New("unreadable settings"), status, now).Allowed {
		t.Fatal("configuration failure allowed browser traffic")
	}
	status.BrowserCheckedAt = now.Add(time.Millisecond)
	if browserDecision(c, nil, status, now).Allowed {
		t.Fatal("a future proof allowed browser traffic")
	}
	c.BrowserProtection = false
	status.BrowserCheckedAt, status.BrowserPolicyKey = now, policyFingerprint(c)
	if browserDecision(c, nil, status, now).Allowed {
		t.Fatal("uninstalled browser integration granted a lease")
	}
}

func TestBrowserLeaseHonorsOnlyExplicitProtectionSuspension(t *testing.T) {
	now := time.Now()
	c := config{BrowserProtection: true}
	status := watchStatus{State: "off", BrowserPolicyKey: policyFingerprint(c)}
	if browserDecision(c, nil, status, now).Allowed {
		t.Fatal("process watcher off implicitly allowed browsing")
	}
	c.ProtectionDisabled = true
	status.BrowserPolicyKey = policyFingerprint(c)
	if got := browserDecision(c, nil, status, now); !got.Allowed || got.State != "disabled" {
		t.Fatalf("explicit suspension ignored: %+v", got)
	}
	c.ProtectionDisabled = false
	deadline := now.Add(time.Minute)
	c.ProtectionPausedUntil = &deadline
	status.BrowserPolicyKey = policyFingerprint(c)
	if got := browserDecision(c, nil, status, now); !got.Allowed || got.State != "paused" {
		t.Fatalf("temporary suspension ignored: %+v", got)
	}
	if browserDecision(c, nil, status, deadline).Allowed {
		t.Fatal("expired suspension did not require a new network proof")
	}
	lastLease := browserDecision(c, nil, status, deadline.Add(-time.Millisecond))
	if !lastLease.Allowed || lastLease.ValidUntil != deadline.UnixMilli() {
		t.Fatal("browser lease extends beyond the explicitly chosen protection pause")
	}
}
