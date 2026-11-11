//go:build linux || windows || freebsd

package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	if len(os.Args) >= 2 {
		switch os.Args[1] {
		case "_gate":
			code, err := launchGate(os.Args[2:])
			finish(code, err)
		case "_fixture":
			tickFixture(os.Args[2], os.Args[3])
		}
	}
	os.Exit(m.Run())
}

func TestNativeAppProcessPauseAndIdentity(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("application observation is restricted to regular user sessions")
	}
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	progress, stop := filepath.Join(dir, "progress"), filepath.Join(dir, "stop")
	cmd := exec.Command(path, "_fixture", progress, stop)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()
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
	var child appProcess
	for _, process := range processes {
		if process.Key.PID == cmd.Process.Pid {
			child = process
			break
		}
	}
	if child.Key.Started == 0 || child.Parent != os.Getpid() || child.Executable == "" {
		t.Fatalf("fixture identity not detected: %+v", child)
	}
	stale := child.Key
	stale.Started++
	if err := controlAppProcess(stale, appPause); !errors.Is(err, os.ErrProcessDone) {
		t.Fatalf("stale identity was accepted: %v", err)
	}
	if err := controlAppProcess(child.Key, appPause); err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)
	frozen := size()
	time.Sleep(300 * time.Millisecond)
	if size() != frozen {
		t.Fatal("fixture ran while paused")
	}
	if err := controlAppProcess(child.Key, appResume); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, 6*time.Second, func() bool { return size() > frozen })
}

func tickFixture(path, stop string) {
	f, err := os.Create(path)
	if err != nil {
		os.Exit(74)
	}
	for {
		if _, err := os.Stat(stop); err == nil {
			f.Close()
			os.Exit(23)
		}
		if _, err := f.Write([]byte{'.'}); err != nil {
			os.Exit(74)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func TestManagedCommandRuntime(t *testing.T) {
	for _, key := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "ANTHROPIC_BASE_URL",
		"OPENAI_BASE_URL", "OPENAI_API_BASE", "CODEX_API_BASE_URL", "CLAUDE_CODE_USE_BEDROCK",
		"CLAUDE_CODE_USE_VERTEX", "CLAUDE_CODE_USE_FOUNDRY"} {
		t.Setenv(key, "")
		t.Setenv(strings.ToLower(key), "")
	}
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	progress := filepath.Join(dir, "progress")
	stop := filepath.Join(dir, "stop")
	command := []string{path, "_fixture", progress, stop}
	var online atomic.Bool
	checks := routeCheck{
		verify: func(context.Context, config) report {
			return report{Trusted: online.Load(), Reason: "fixture"}
		},
		routes: func(context.Context, string) (bool, error) {
			if !online.Load() {
				return false, errors.New("fixture link down")
			}
			return false, nil
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 22*time.Second)
	defer cancel()
	c := config{Adapter: "fixture"}
	if code, err := startManaged(ctx, command, c, checks, streams{}, func(runState, string) {}); code != 69 || err == nil {
		t.Fatalf("untrusted launch: %d, %v", code, err)
	}
	if _, err := os.Stat(progress); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("denied command ran: %v", err)
	}

	online.Store(true)
	result := make(chan int, 1)
	logs := make(chan string, 24)
	go func() {
		code, err := startManaged(ctx, command, c, checks, streams{err: os.Stderr}, func(_ runState, line string) { logs <- line })
		if err != nil {
			t.Log(err)
		}
		result <- code
	}()
	defer func() {
		cancel()
		select {
		case <-result:
		case <-time.After(4 * time.Second):
		}
	}()

	size := func() int64 {
		if info, err := os.Stat(progress); err == nil {
			return info.Size()
		}
		return 0
	}
	waitUntil(t, 8*time.Second, func() bool { return size() >= 4 })
	online.Store(false)
	waitUntil(t, 3*time.Second, func() bool {
		select {
		case event := <-logs:
			return strings.HasPrefix(event, "paused ")
		default:
			return false
		}
	})
	time.Sleep(300 * time.Millisecond)
	paused := size()
	time.Sleep(300 * time.Millisecond)
	if size() != paused {
		t.Fatal("program kept executing after pause")
	}
	online.Store(true)
	waitUntil(t, 10*time.Second, func() bool { return size() > paused })
	if err := os.WriteFile(stop, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case code := <-result:
		result <- code
		if code != 23 {
			t.Fatalf("exit code = %d, expected 23", code)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("program did not exit")
	}
}

func waitUntil(t *testing.T, timeout time.Duration, ready func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if ready() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("timed out waiting for the process fixture")
}
