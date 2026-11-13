package main

import (
	"errors"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestWindowsRecoverThreadLeases(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	progress := filepath.Join(dir, "progress")
	command := exec.Command(executable, "_fixture", progress, filepath.Join(dir, "stop"))
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = command.Process.Kill()
		_ = command.Wait()
	})
	size := func() int64 {
		if info, err := os.Stat(progress); err == nil {
			return info.Size()
		}
		return 0
	}
	waitUntil(t, 6*time.Second, func() bool { return size() >= 4 })
	processes, err := listAppProcesses()
	if err != nil {
		t.Fatal(err)
	}
	var key appProcessKey
	for _, process := range processes {
		if process.Key.PID == command.Process.Pid {
			key = process.Key
			break
		}
	}
	if key.Started == 0 {
		t.Fatal("fixture identity missing from the process snapshot")
	}
	forgetLeases := func() {
		appPausesMu.Lock()
		defer appPausesMu.Unlock()
		closeWindowsAppThreads(appPauses[key].threads)
		delete(appPauses, key)
	}
	t.Cleanup(forgetLeases)
	if err := controlAppProcess(key, appPause); err != nil {
		t.Fatal(err)
	}
	leases := appThreadLeases(key)
	if len(leases) == 0 {
		t.Fatal("pause did not record thread identities")
	}

	// A crashed guardian loses its handles while Windows retains the counts.
	forgetLeases()
	stale := leases[0]
	stale.Started++
	if err := adoptAppThreadLeases(key, []appThreadLease{stale}); err != nil {
		t.Fatal(err)
	}
	if len(appThreadLeases(key)) != 0 {
		t.Fatal("a thread with a different creation time was adopted")
	}
	wrongKey := key
	wrongKey.Started++
	if err := adoptAppThreadLeases(wrongKey, leases); !errors.Is(err, os.ErrProcessDone) {
		t.Fatalf("stale process identity was accepted: %v", err)
	}

	external, err := openWindowsAppThread(uint32(key.PID), leases[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = windows.CloseHandle(external.handle) })
	externalPause := func() {
		t.Helper()
		previous, _, err := suspendThread.Call(uintptr(external.handle))
		if uint32(previous) == math.MaxUint32 {
			t.Fatal(err)
		}
		if uint32(previous) != leases[0].Count {
			t.Fatalf("suspend count = %d, want %d", previous, leases[0].Count)
		}
	}
	releaseExternalPause := func() {
		t.Helper()
		previous, err := windows.ResumeThread(external.handle)
		if err != nil || previous != leases[0].Count+1 {
			t.Fatalf("external suspend count was changed: %d, %v", previous, err)
		}
	}
	externalPause()
	if err := adoptAppThreadLeases(key, leases); err == nil || len(appThreadLeases(key)) != 0 {
		t.Fatalf("changed count was accepted by recovery: %v", err)
	}
	releaseExternalPause()
	if err := adoptAppThreadLeases(key, leases); err != nil {
		t.Fatal(err)
	}
	if len(appThreadLeases(key)) != len(leases) {
		t.Fatal("recovering a confirmed pause lost a thread lease")
	}
	externalPause()
	if err := controlAppProcess(key, appResume); err == nil {
		t.Fatal("resume accepted an externally changed count after recovery")
	}
	releaseExternalPause()
	if err := controlAppProcess(key, appResume); err != nil {
		t.Fatal(err)
	}
	lastSize := size()
	waitUntil(t, 6*time.Second, func() bool { return size() > lastSize })
	if len(appThreadLeases(key)) != 0 {
		t.Fatal("resume left an owned thread lease")
	}
}

func TestWindowsInventoryRejectsReusedPIDMetadata(t *testing.T) {
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, uint32(os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(process)
	key, err := windowsAppProcessIdentity(process, os.Getpid(), 0)
	if err != nil {
		t.Fatal(err)
	}
	stale := key
	stale.Started--
	appInventoryMu.Lock()
	appInventory = map[appProcessKey]appProcess{stale: {Key: stale, Executable: `C:\stale\Claude.exe`, Parent: 1}}
	appInventoryMu.Unlock()
	processes, err := listAppProcesses()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range processes {
		if p.Key.PID == key.PID {
			found = true
			if p.Key != key || p.Executable == `C:\stale\Claude.exe` {
				t.Fatal("metadata for a reused PID affected process identification")
			}
		}
	}
	if !found {
		t.Fatal("current process missing from the inventory")
	}
	appInventoryMu.Lock()
	defer appInventoryMu.Unlock()
	if _, kept := appInventory[stale]; kept {
		t.Fatal("an exited process identity was retained by the cache")
	}
}

func TestWindowsBatchPreservesSuspensionOwnership(t *testing.T) {
	// Build a maintenance snapshot before the fixture exists. Its first pause
	// must not reuse this stale inventory and miss all of its new threads.
	finishInitial := beginWindowsAppProcessBatch()
	t.Cleanup(func() {
		if finishInitial != nil {
			finishInitial()
		}
	})
	appPausesMu.Lock()
	_, snapshotErr := windowsAppThreadIDs(uint32(os.Getpid()), true)
	appPausesMu.Unlock()
	if snapshotErr != nil {
		t.Fatal(snapshotErr)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	progress := filepath.Join(dir, "progress")
	command := exec.Command(executable, "_fixture", progress, filepath.Join(dir, "stop"))
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = command.Process.Kill()
		_ = command.Wait()
	})
	size := func() int64 {
		if info, err := os.Stat(progress); err == nil {
			return info.Size()
		}
		return 0
	}
	waitUntil(t, 6*time.Second, func() bool { return size() >= 4 })
	processes, err := listAppProcesses()
	if err != nil {
		t.Fatal(err)
	}
	var key appProcessKey
	for _, p := range processes {
		if p.Key.PID == command.Process.Pid {
			key = p.Key
		}
	}
	if key.Started == 0 {
		t.Fatal("fixture missing from inventory")
	}
	t.Cleanup(func() { _ = controlAppProcess(key, appResume) })
	if err := controlAppProcess(key, appPause); err != nil {
		t.Fatal(err)
	}
	finishInitial()
	finishInitial = nil
	for range 3 {
		finish := beginWindowsAppProcessBatch()
		err := controlAppProcess(key, appPause)
		if err == nil {
			err = controlAppProcess(key, appPause)
		}
		finish()
		if err != nil {
			t.Fatal(err)
		}
		for _, lease := range appThreadLeases(key) {
			thread, err := openWindowsAppThread(uint32(key.PID), lease.ID)
			if errors.Is(err, os.ErrProcessDone) {
				continue
			}
			if err != nil {
				t.Fatal(err)
			}
			count, err := windowsAppThreadSuspendCount(thread.handle)
			_ = windows.CloseHandle(thread.handle)
			if err != nil || count != 1 {
				t.Fatalf("repeated batch accumulated a suspension: count=%d err=%v", count, err)
			}
		}
	}
	pausedAt := size()
	time.Sleep(150 * time.Millisecond)
	if size() != pausedAt {
		t.Fatal("fixture continued running while the batch owned its pause")
	}
	if err := controlAppProcess(key, appResume); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, 6*time.Second, func() bool { return size() > pausedAt })
}

func BenchmarkWindowsProcessInventory(b *testing.B) {
	if _, err := listAppProcesses(); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := listAppProcesses(); err != nil {
			b.Fatal(err)
		}
	}
}
