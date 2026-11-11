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
