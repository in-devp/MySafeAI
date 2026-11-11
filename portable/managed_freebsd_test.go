//go:build freebsd && cgo

package main

import (
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestFreeBSDManagedPreservesExternalStop(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("managed FreeBSD control uses unprivileged process identities")
	}
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := listener.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	const command = `
		/bin/sleep 60 &
		external=$!
		kill -STOP "$external"
		printf '%s\n' "$external" > "$1/external"
		(
			/bin/sleep 60 &
			printf '%s\n' "$!" > "$1/orphan"
		) &
		wait "$!"
		/bin/sleep 60 &
		active=$!
		printf '%s\n' "$active" > "$1/active"
		wait "$active"
	`
	token := secret()
	cmd := exec.Command(self, "_gate", listener.Addr().String(), token, "/bin/sh", "-c", command, "fixture", dir)
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	defer func() {
		select {
		case <-done:
		case <-time.After(4 * time.Second):
			_ = cmd.Process.Kill()
			<-done
			t.Error("managed gate did not exit on connection close")
		}
	}()

	gate, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Close()
	if err := gate.SetDeadline(time.Now().Add(4 * time.Second)); err != nil {
		t.Fatal(err)
	}
	received := make([]byte, len(token))
	if _, err := io.ReadFull(gate, received); err != nil || string(received) != token {
		t.Fatalf("invalid gate handshake: %v", err)
	}
	if _, err := gate.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	tree := &freeBSDTree{gate: gate}

	find := func(name string) appProcess {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return appProcess{}
		}
		pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
		if err != nil || pid <= 1 {
			return appProcess{}
		}
		processes, err := listAppProcesses()
		if err != nil {
			t.Fatal(err)
		}
		for _, process := range processes {
			if process.Key.PID == pid {
				return process
			}
		}
		return appProcess{}
	}
	waitUntil(t, 5*time.Second, func() bool {
		return find("external").Stopped && find("active").Key.PID > 1 &&
			find("orphan").Parent == cmd.Process.Pid
	})
	if err := tree.update(true); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, 3*time.Second, func() bool {
		return find("active").Stopped && find("orphan").Stopped
	})
	if err := tree.update(false); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, 3*time.Second, func() bool {
		active, orphan := find("active"), find("orphan")
		return active.Key.PID > 1 && !active.Stopped && orphan.Key.PID > 1 && !orphan.Stopped
	})
	if !find("external").Stopped {
		t.Fatal("resume released a descendant stopped independently of the monitor")
	}
}
