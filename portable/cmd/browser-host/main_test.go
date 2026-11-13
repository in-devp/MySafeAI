package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/in-devp/MySafeAI/portable/browserbridge"
)

func TestNativeHostSubprocess(t *testing.T) {
	if os.Getenv("MYSAFEAI_BRIDGE_TEST_PROCESS") != "1" {
		return
	}
	for index, arg := range os.Args {
		if arg == "--" {
			os.Args = append([]string{os.Args[0]}, os.Args[index+1:]...)
			main()
			os.Exit(0)
		}
	}
	os.Exit(2)
}

func TestBrowserHostRoundTripAndLostApplication(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "config")
	if runtime.GOOS == "darwin" {
		config = filepath.Join(dir, "Library", "Application Support")
	}
	statePath := filepath.Join(config, "MySafeAI", browserbridge.SnapshotFilename)
	if err := os.MkdirAll(filepath.Dir(statePath), 0o700); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	state := browserbridge.Snapshot{Protocol: 1, Allowed: true, State: "trusted", UpdatedAt: now.UnixMilli(), ValidUntil: now.Add(3 * time.Second).UnixMilli()}
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, executable, "-test.run=^TestNativeHostSubprocess$", "--", browserbridge.ChromiumOrigin)
	for _, item := range os.Environ() {
		name, _, _ := strings.Cut(item, "=")
		if !strings.EqualFold(name, "HOME") && !strings.EqualFold(name, "APPDATA") && name != "XDG_CONFIG_HOME" && name != "MYSAFEAI_BRIDGE_TEST_PROCESS" {
			command.Env = append(command.Env, item)
		}
	}
	command.Env = append(command.Env, "HOME="+dir, "APPDATA="+config, "XDG_CONFIG_HOME="+config, "MYSAFEAI_BRIDGE_TEST_PROCESS=1")
	input, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = command.Process.Kill() })
	// Refresh after launching, so a heavily loaded CI runner doesn't consume
	// the lease while creating the helper process.
	now = time.Now()
	state.UpdatedAt, state.ValidUntil = now.UnixMilli(), now.Add(3*time.Second).UnixMilli()
	data, err = json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	query := func() browserbridge.Response {
		t.Helper()
		body := []byte(`{"op":"status"}`)
		if err := binary.Write(input, binary.LittleEndian, uint32(len(body))); err != nil {
			t.Fatal(err)
		}
		if _, err := input.Write(body); err != nil {
			t.Fatal(err)
		}
		var size uint32
		if err := binary.Read(output, binary.LittleEndian, &size); err != nil {
			t.Fatal(err)
		}
		if size > browserbridge.MaxFrameSize {
			t.Fatal("unexpected protocol output")
		}
		message := make([]byte, size)
		if _, err := io.ReadFull(output, message); err != nil {
			t.Fatal(err)
		}
		var response browserbridge.Response
		if err := json.Unmarshal(message, &response); err != nil {
			t.Fatal(err)
		}
		return response
	}
	if r := query(); !r.Allowed || r.State != "trusted" {
		t.Fatalf("valid state denied: %+v", r)
	}
	if err := os.Remove(statePath); err != nil {
		t.Fatal(err)
	}
	if r := query(); r.Allowed || r.State != "unavailable" {
		t.Fatalf("lost application allowed: %+v", r)
	}
	if err := input.Close(); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err != nil {
		t.Fatal(err)
	}
	if stderr.Len() != 0 {
		t.Fatalf("unexpected helper diagnostics: %s", stderr.String())
	}
}
