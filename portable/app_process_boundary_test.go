package main

import (
	"context"
	"slices"
	"testing"
	"time"
)

func TestVPNEngineStopsInheritedIDEProtection(t *testing.T) {
	for _, engine := range []string{
		"sing-box", "sing_box", "mihomo", "clash", "wireguard-go", "openvpn", "tailscaled",
		"xray", "v2ray", "hysteria", "hysteria2", "tuic-client", "ss-local", "sslocal", "warp-svc",
	} {
		t.Run(engine, func(t *testing.T) {
			processes := []appProcess{
				fixtureProcess(900101, 0, 1, "/apps/Cursor.exe"),
				fixtureProcess(900102, 900101, 2, "/shell/powershell.exe"),
				fixtureProcess(900103, 900102, 3, "/vpn/"+engine+".exe"),
				fixtureProcess(900104, 900103, 4, "/vpn/helper.exe"),
				fixtureProcess(900105, 900102, 5, "/tools/curl.exe"),
				fixtureProcess(900106, 900104, 6, "/tools/codex.exe"),
				fixtureProcess(900107, 900106, 7, "/tools/git.exe"),
				fixtureProcess(900108, 900102, 8, "/browser/chrome.exe"),
				fixtureProcess(900109, 900108, 9, "/browser/chrome.exe"),
			}
			got := watchedProcesses(processes, builtInTargets, 1)
			byPID := make(map[int][]string)
			for _, item := range got {
				byPID[item.Key.PID] = item.targets
			}
			if len(got) != 7 || len(byPID[900103]) != 0 || len(byPID[900104]) != 0 {
				t.Fatalf("IDE inheritance captured VPN or helper: %+v", got)
			}
			for _, pid := range []int{900101, 900102, 900105, 900108, 900109} {
				if !slices.Equal(byPID[pid], []string{"cursor"}) {
					t.Fatalf("ordinary agent/browser child %d lost protection: %v", pid, byPID[pid])
				}
			}
			for _, pid := range []int{900106, 900107} {
				if !slices.Equal(byPID[pid], []string{"codex-cli"}) {
					t.Fatalf("Codex after VPN boundary %d has wrong rules: %v", pid, byPID[pid])
				}
			}
		})
	}
}

func TestVPNEngineExplicitCustomSelectionStillProtectsChildren(t *testing.T) {
	processes := []appProcess{
		fixtureProcess(900201, 0, 1, "/apps/cursor"),
		fixtureProcess(900202, 900201, 2, "/vpn/sing-box"),
		fixtureProcess(900203, 900202, 3, "/vpn/helper"),
		fixtureProcess(900204, 900203, 4, "/vpn/mihomo"),
	}
	targets := append(append([]appTarget(nil), builtInTargets...), appTarget{ID: "custom-vpn", Executable: "/vpn/sing-box"})
	got := watchedProcesses(processes, targets, 1)
	if len(got) != 4 {
		t.Fatalf("explicit target disappeared: %+v", got)
	}
	for _, item := range got {
		if item.Key.PID != 900201 && !slices.Equal(item.targets, []string{"custom-vpn"}) {
			t.Fatalf("explicit VPN target has wrong inherited rules: %+v", item)
		}
	}
}

func TestRecoveredInheritedVPNPausesAreReleased(t *testing.T) {
	cursor := fixtureProcess(900301, 0, 1, "/apps/cursor")
	vpn := fixtureProcess(900302, cursor.Key.PID, 2, "/vpn/mihomo")
	helper := fixtureProcess(900303, vpn.Key.PID, 3, "/vpn/helper")
	codex := fixtureProcess(900304, helper.Key.PID, 4, "/tools/codex")
	curl := fixtureProcess(900305, cursor.Key.PID, 5, "/tools/curl")
	processes := []appProcess{cursor, vpn, helper, codex, curl}
	s := storage{t.TempDir()}
	now := time.Now()
	var records []pauseRecord
	for i := range processes {
		processes[i].Stopped = true
		records = append(records, pauseRecord{Key: processes[i].Key, Targets: []string{"cursor"},
			Depth: i + 1, Phase: "owned", Started: now})
	}
	if err := s.saveJSON("observer-pauses.json", records); err != nil {
		t.Fatal(err)
	}
	type action struct {
		pid    int
		action appProcessAction
	}
	var actions []action
	watch := newAppWatch(s, processBackend{
		list: func() ([]appProcess, error) { return processes, nil },
		signal: func(key appProcessKey, control appProcessAction) error {
			actions = append(actions, action{key.PID, control})
			return nil
		},
	})
	watch.reconcile(context.Background(), now, builtInTargets, nil)
	var resumed []int
	for _, item := range actions {
		if item.action == appResume {
			resumed = append(resumed, item.pid)
		}
	}
	if !slices.Equal(resumed, []int{helper.Key.PID, vpn.Key.PID}) {
		t.Fatalf("wrong recovered VPN releases: %v", resumed)
	}
	if _, kept := watch.pauses[vpn.Key]; kept {
		t.Fatal("old inherited VPN lease survived recovery")
	}
	if _, kept := watch.pauses[curl.Key]; !kept {
		t.Fatal("curl protection was weakened")
	}
	if !slices.Equal(watch.pauses[codex.Key].Targets, []string{"codex-cli"}) {
		t.Fatalf("independent Codex rule lost during recovery: %+v", watch.pauses[codex.Key])
	}
}

func TestDetachedVPNBoundaryDoesNotTrustAReusedParentPID(t *testing.T) {
	// The old child's process is older than the new VPN reusing its parent PID.
	child := fixtureProcess(900402, 900401, 1, "/tools/curl")
	newVPN := fixtureProcess(900401, 0, 3, "/vpn/mihomo")
	watch := newAppWatch(storage{t.TempDir()}, processBackend{})
	watch.remembered[child.Key] = watchedProcess{appProcess: child, targets: []string{"cursor"}, depth: 2}
	got := watch.includeDetached(nil, []appProcess{newVPN, child}, builtInTargets)
	if len(got) != 1 || got[0].Key != child.Key {
		t.Fatalf("a reused parent PID released the detached child: %+v", got)
	}
}

func TestRecoveredExplicitVPNSelectionStaysPaused(t *testing.T) {
	cursor := fixtureProcess(900501, 0, 1, "/apps/cursor")
	vpn := fixtureProcess(900502, cursor.Key.PID, 2, "/vpn/openvpn")
	vpn.Stopped = true
	s := storage{t.TempDir()}
	now := time.Now()
	if err := s.saveJSON("observer-pauses.json", []pauseRecord{{Key: vpn.Key, Targets: []string{"cursor"},
		Phase: "owned", Started: now}}); err != nil {
		t.Fatal(err)
	}
	watch := newAppWatch(s, processBackend{
		list: func() ([]appProcess, error) { return []appProcess{cursor, vpn}, nil },
		signal: func(key appProcessKey, action appProcessAction) error {
			if key == vpn.Key && action == appResume {
				t.Fatal("explicitly selected VPN was resumed by the inheritance exception")
			}
			return nil
		},
	})
	targets := append(append([]appTarget(nil), builtInTargets...), appTarget{ID: "custom-vpn", Executable: vpn.Executable})
	watch.reconcile(context.Background(), now, targets, nil)
	if !slices.Equal(watch.pauses[vpn.Key].Targets, []string{"custom-vpn"}) {
		t.Fatalf("explicit VPN rule missing after recovery: %+v", watch.pauses[vpn.Key])
	}
}

func TestDetachedExplicitVPNSubtreeKeepsCustomRule(t *testing.T) {
	vpn := fixtureProcess(900601, 0, 3, "/vpn/mihomo")
	helper := fixtureProcess(900602, vpn.Key.PID, 4, "/vpn/helper")
	watch := newAppWatch(storage{t.TempDir()}, processBackend{})
	for _, process := range []appProcess{vpn, helper} {
		watch.remembered[process.Key] = watchedProcess{appProcess: process, targets: []string{"cursor", "custom-vpn"}, depth: 2}
	}
	// The explicitly selected original VPN parent has exited; its remembered
	// custom rule must still protect the secondary transport and its helpers.
	targets := append(append([]appTarget(nil), builtInTargets...), appTarget{ID: "custom-vpn", Executable: "/vpn/sing-box"})
	got := watch.includeDetached(nil, []appProcess{vpn, helper}, targets)
	if len(got) != 2 {
		t.Fatalf("explicit detached VPN subtree disappeared: %+v", got)
	}
	for _, process := range got {
		if !slices.Equal(process.targets, []string{"custom-vpn"}) {
			t.Fatalf("wrong recovered rules for detached VPN subtree: %+v", process)
		}
	}
}
