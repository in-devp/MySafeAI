package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func fixtureProcess(pid, parent int, order uint64, executable string, arguments ...string) appProcess {
	return appProcess{Key: appProcessKey{PID: pid, Started: order + 1000}, Parent: parent,
		Order: order, Executable: executable, Arguments: arguments}
}

func TestWatchSeparatesManagedAndReusedParents(t *testing.T) {
	processes := []appProcess{
		fixtureProcess(10, 0, 1, "/usr/bin/zsh"),
		fixtureProcess(11, 10, 2, "/usr/bin/mysafeai"),
		fixtureProcess(12, 11, 3, "/usr/bin/mysafeai", "mysafeai", "_gate"),
		fixtureProcess(13, 12, 4, "/usr/bin/codex"),
		fixtureProcess(14, 13, 5, "/usr/bin/git"),
		fixtureProcess(20, 10, 6, "/usr/bin/node", "node", "/npm/@openai/codex/bin/codex.js"),
		fixtureProcess(21, 20, 7, "/usr/bin/curl"),
		fixtureProcess(22, 20, 5, "/usr/bin/unrelated"),
		fixtureProcess(23, 21, 8, "/usr/bin/claude"),
	}
	watched := watchedProcesses(processes, builtInTargets, 11)
	if len(watched) != 3 || watched[0].Key.PID != 20 || watched[1].Key.PID != 21 || watched[2].Key.PID != 23 {
		t.Fatalf("wrong process tree: %+v", watched)
	}
	if !slices.Equal(watched[2].targets, []string{"codex-cli", "claude-code"}) {
		t.Fatalf("lost overlapping protection: %+v", watched[2])
	}
}

func TestWatchDoesNotResumeExternalStops(t *testing.T) {
	// Use PIDs above the host range so this fixture cannot collide with the test runner.
	root := fixtureProcess(900001, 0, 1, "/usr/bin/codex")
	child := fixtureProcess(900002, root.Key.PID, 2, "/usr/bin/git")
	external := fixtureProcess(900003, root.Key.PID, 3, "/usr/bin/curl")
	external.Stopped = true
	type signal struct {
		key    appProcessKey
		action appProcessAction
	}
	var signals []signal
	processes := []appProcess{root, child, external}
	watch := newAppWatch(storage{t.TempDir()}, processBackend{
		list: func() ([]appProcess, error) { return processes, nil },
		signal: func(key appProcessKey, action appProcessAction) error {
			signals = append(signals, signal{key, action})
			for i := range processes {
				if processes[i].Key == key {
					processes[i].Stopped = action == appPause
				}
			}
			return nil
		},
	})
	now := time.Now()
	watch.reconcile(context.Background(), now, builtInTargets, nil)
	if !slices.Equal(signals, []signal{{root.Key, appPause}, {child.Key, appPause}}) {
		t.Fatalf("wrong pauses: %+v", signals)
	}
	signals = nil
	watch.proofs["codex-cli"] = policyProof{report: report{Trusted: true}, checked: now}
	watch.reconcile(context.Background(), now, builtInTargets, nil)
	if !slices.Equal(signals, []signal{{child.Key, appResume}, {root.Key, appResume}}) {
		t.Fatalf("wrong resumes: %+v", signals)
	}
	if !processes[2].Stopped {
		t.Fatal("resumed an independently paused process")
	}
}

func TestInvalidConfigurationDoesNotReleaseRecoveredApplications(t *testing.T) {
	item := fixtureProcess(900011, 0, 1, "/some/custom-app")
	item.Stopped = true
	s := storage{t.TempDir()}
	records := []pauseRecord{{Key: item.Key, Targets: []string{"custom-example"}, Phase: "owned", Started: time.Now()}}
	if err := s.saveJSON("observer-pauses.json", records); err != nil {
		t.Fatal(err)
	}
	watch := newAppWatch(s, processBackend{
		list: func() ([]appProcess, error) { return []appProcess{item}, nil },
		signal: func(key appProcessKey, action appProcessAction) error {
			if action == appResume {
				t.Fatalf("invalid configuration released %v", key)
			}
			return nil
		},
	})
	watch.reconcile(context.Background(), time.Now(), builtInTargets, os.ErrInvalid)
	if _, ok := watch.pauses[item.Key]; !ok {
		t.Fatal("lost the recorded pause")
	}
}

func TestManagedTargetsIncludeBothPresetAndCustomRule(t *testing.T) {
	c := config{CustomTargets: []appTarget{{ID: "custom-codex", Executable: "/opt/codex"}}}
	if ids := c.commandTargets([]string{"/opt/codex"}); !slices.Equal(ids, []string{"codex-cli", "custom-codex"}) {
		t.Fatalf("incorrect managed rule precedence: %v", ids)
	}
}

func TestPendingPreflightUsesTheManagedRulesWithoutAnExistingProcess(t *testing.T) {
	s := storage{t.TempDir()}
	disabled := false
	c := config{Watch: &disabled, Rules: map[string]appConnectionRule{"codex-cli": {Allowed: []string{"203.0.113.1"}}}}
	if err := s.save(c); err != nil {
		t.Fatal(err)
	}
	proof := report{target: "codex-cli", routeKey: "current-route", IPs: []string{"203.0.113.2"}, Mode: "tunnel"}
	s.offerPreflight("preflight-fixture.json", c, proof)
	pending := s.pendingPreflights(time.Now())
	if len(pending) != 1 || pending[0].Target != "codex-cli" || pending[0].ProbeTarget != "codex-cli" {
		t.Fatalf("preflight did not offer the app-specific IP: %+v", pending)
	}
	c.Adapter = "changed"
	if err := s.save(c); err != nil {
		t.Fatal(err)
	}
	if len(s.pendingPreflights(time.Now())) != 0 {
		t.Fatal("published a proposal for an old policy")
	}
}

func TestBasicPolicyEditPreservesAdvancedRules(t *testing.T) {
	s := storage{t.TempDir()}
	if err := os.WriteFile(filepath.Join(s.dir, "portable.json"), []byte(`{"adapter":"vpn","allowed":["203.0.113.42"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	legacy, err := s.load()
	if err != nil || legacy.Adapter != "vpn" || len(legacy.activeTargets()) != len(builtInTargets) {
		t.Fatalf("legacy configuration: %+v %v", legacy, err)
	}
	legacy.Rules = map[string]appConnectionRule{"codex-cli": {Allowed: []string{}, Countries: []string{}}}
	legacy.Sources = []sourcePreference{{Name: "Test", URL: "https://test.example/ip"}}
	if err := s.save(legacy); err != nil {
		t.Fatal(err)
	}
	p := &panel{storage: s, token: "session"}
	request := httptest.NewRequest(http.MethodPost, "/api/policy", bytes.NewBufferString(`{"adapter":"new","allowed":["203.0.113.43"]}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-MySafeAI-Token", p.token)
	reply := httptest.NewRecorder()
	p.handler().ServeHTTP(reply, request)
	var changed config
	if reply.Code != http.StatusOK || json.Unmarshal(reply.Body.Bytes(), &changed) != nil {
		t.Fatalf("cannot save basic policy: %d %s", reply.Code, reply.Body)
	}
	effective, _ := changed.forTarget("codex-cli")
	if changed.Adapter != "new" || len(changed.Sources) != 1 || effective.Allowed == nil || len(effective.Allowed) != 0 {
		t.Fatalf("legacy form erased rules: %+v", changed)
	}
}

func TestConsensusRequiresDistinctHostsAndRejectsDisagreement(t *testing.T) {
	probes := []probe{
		{Name: "AWS", IP: "203.0.113.42", host: "example.com"},
		{Name: "Same host", IP: "203.0.113.42", host: "example.com"},
	}
	if _, err := consensus(probes, false); err == nil {
		t.Fatal("two paths on one source counted as independent")
	}
	probes = append(probes, probe{Name: "Other", IP: "203.0.113.42", host: "other.example"})
	if ips, err := consensus(probes, false); err != nil || len(ips) != 1 {
		t.Fatalf("agreement was rejected: %v %v", ips, err)
	}
	probes = append(probes, probe{Name: "Disagrees", IP: "203.0.113.43", host: "third.example"})
	if _, err := consensus(probes, false); err == nil {
		t.Fatal("accepted disagreeing providers")
	}
}

func TestBashWSResultsAreDiagnosticOnly(t *testing.T) {
	if validObserverID("https://other.example") || validObserverID("a.b") || !validObserverID("0123456789abcdef") {
		t.Fatal("invalid bash.ws session validation")
	}
	data := []byte(`[{"type":"ip","ip":"203.0.113.42"},{"type":"dns","ip":"2001:0db8::53","org":"Example"},{"type":"dns","ip":"2001:db8::53"},{"type":"conclusion","text":"no leak"}]`)
	resolvers, err := parseObservedResolvers(data)
	if err != nil || len(resolvers) != 1 || resolvers[0].IP != "2001:db8::53" {
		t.Fatalf("invalid resolver report: %v %v", resolvers, err)
	}
}
