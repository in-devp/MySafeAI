package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type runState string

const (
	runChecking runState = "checking"
	runRunning  runState = "running"
	runPaused   runState = "paused"
	runExited   runState = "exited"
)

type processTree interface {
	update(paused bool) error
	close()
}

type streams struct {
	in, out, err *os.File
}

type routeCheck struct {
	verify func(context.Context, config) report
	routes func(context.Context, string) (bool, error)
}

var liveCheck = routeCheck{verify, routes}

func secret() string {
	var token [24]byte
	rand.Read(token[:])
	return hex.EncodeToString(token[:])
}

func executable(args []string) ([]string, error) {
	if len(args) == 0 {
		return nil, errors.New("specify a command after --")
	}
	for _, entry := range os.Environ() {
		key, value, _ := strings.Cut(entry, "=")
		switch strings.ToUpper(key) {
		case "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "ANTHROPIC_BASE_URL", "OPENAI_BASE_URL", "OPENAI_API_BASE", "CODEX_API_BASE_URL",
			"CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX", "CLAUDE_CODE_USE_FOUNDRY":
			if value != "" {
				return nil, fmt.Errorf("unset %s before a managed launch", key)
			}
		}
	}
	path, err := exec.LookPath(args[0])
	if err != nil {
		return nil, err
	}
	switch strings.ToLower(filepath.Ext(path)) {
	case ".bat", ".cmd", ".ps1":
		return nil, errors.New("use a native .exe or call the CLI's script with its interpreter explicitly")
	}
	path, err = filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	return append([]string{path}, args[1:]...), nil
}

func startManaged(ctx context.Context, args []string, c config, checks routeCheck, stdio streams, log func(runState, string)) (int, error) {
	target, err := executable(args)
	if err != nil {
		return 126, err
	}
	proof := checks.verify(ctx, c)
	if !proof.Trusted {
		return 69, errors.New(proof.Reason)
	}
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return 70, err
	}
	defer listener.Close()
	token := secret()
	self, err := os.Executable()
	if err != nil {
		return 70, err
	}
	helper := exec.Command(self, append([]string{"_gate", listener.Addr().String(), token}, target...)...)
	if stdio.in != nil {
		helper.Stdin = stdio.in
	}
	if stdio.out != nil {
		helper.Stdout = stdio.out
	}
	if stdio.err != nil {
		helper.Stderr = stdio.err
	}
	if err := helper.Start(); err != nil {
		return 70, err
	}
	exited := make(chan error, 1)
	go func() { exited <- helper.Wait() }()
	var finished bool
	defer func() {
		if finished {
			return
		}
		select {
		case <-exited:
		case <-time.After(3 * time.Second):
			_ = helper.Process.Kill()
			<-exited
		}
	}()

	tree, err := openTree(helper.Process.Pid)
	if err != nil {
		_ = helper.Process.Kill()
		return 70, fmt.Errorf("cannot secure the command's process tree: %w", err)
	}
	defer tree.close()
	_ = listener.SetDeadline(time.Now().Add(4 * time.Second))
	gate, err := listener.AcceptTCP()
	if err != nil {
		return 70, err
	}
	defer gate.Close()
	_ = listener.Close()
	_ = gate.SetDeadline(time.Now().Add(4 * time.Second))
	received := make([]byte, len(token))
	if _, err := io.ReadFull(gate, received); err != nil || subtle.ConstantTimeCompare(received, []byte(token)) != 1 {
		return 70, errors.New("invalid local launch handshake")
	}
	checkCtx, cancel := context.WithTimeout(ctx, time.Second)
	ipv6, err := checks.routes(checkCtx, c.Adapter)
	cancel()
	if err != nil || ipv6 != proof.IPv6 {
		return 69, errors.New("the route changed before launch")
	}
	if _, err := gate.Write([]byte{1}); err != nil {
		return 70, err
	}
	_ = gate.SetDeadline(time.Time{})
	log(runRunning, "started "+filepath.Base(target[0]))

	routeTick := time.NewTicker(500 * time.Millisecond)
	proofTick := time.NewTicker(5 * time.Second)
	defer routeTick.Stop()
	defer proofTick.Stop()
	recheckCtx, stopChecks := context.WithCancel(ctx)
	defer stopChecks()
	results := make(chan report, 1)
	checking := false
	paused := false
	generation := uint64(0)
	var proofGeneration uint64
	routeOK, previousIPv6 := true, proof.IPv6
	lastVerified := time.Now()
	for {
		select {
		case err := <-exited:
			finished = true
			log(runExited, "exited "+filepath.Base(target[0]))
			var exit *exec.ExitError
			if errors.As(err, &exit) {
				return exit.ExitCode(), nil
			}
			return 0, err
		case <-ctx.Done():
			return 130, nil
		case <-routeTick.C:
			checkCtx, cancel := context.WithTimeout(ctx, time.Second)
			ipv6, err := checks.routes(checkCtx, c.Adapter)
			cancel()
			ok := err == nil
			if ok != routeOK || ipv6 != previousIPv6 {
				generation++
				routeOK, previousIPv6 = ok, ipv6
			}
			if !ok || ipv6 != proof.IPv6 || time.Since(lastVerified) > 12*time.Second {
				if !paused {
					log(runPaused, "paused "+filepath.Base(target[0])+" · route changed")
				}
				paused = true
			}
			if err := tree.update(paused); err != nil {
				return 70, fmt.Errorf("process control failed: %w", err)
			}
		case <-proofTick.C:
			if !checking {
				checking = true
				proofGeneration = generation
				go func() { results <- checks.verify(recheckCtx, c) }()
			}
		case result := <-results:
			checking = false
			trusted := result.Trusted && proofGeneration == generation
			if trusted {
				checkCtx, cancel := context.WithTimeout(ctx, time.Second)
				ipv6, err := checks.routes(checkCtx, c.Adapter)
				cancel()
				trusted = err == nil && ipv6 == result.IPv6
			}
			if trusted {
				proof = result
				lastVerified = time.Now()
			}
			if !trusted && result.Trusted {
				result.Reason = "the route changed during verification"
			}
			if trusted == paused {
				paused = !trusted
				state, action := runRunning, "resumed "
				if paused {
					state, action = runPaused, "paused "
				}
				log(state, action+filepath.Base(target[0])+" · "+result.Reason)
			}
			if err := tree.update(paused); err != nil {
				return 70, fmt.Errorf("process control failed: %w", err)
			}
		}
	}
}

func launchGate(args []string) (int, error) {
	if len(args) < 3 || !filepath.IsAbs(args[2]) || len(args[1]) != 48 {
		return 64, errors.New("invalid launch arguments")
	}
	address, err := net.ResolveTCPAddr("tcp4", args[0])
	if err != nil || !address.IP.IsLoopback() {
		return 64, errors.New("the launch gate must be local")
	}
	gate, err := net.DialTimeout("tcp4", address.String(), 4*time.Second)
	if err != nil {
		return 70, err
	}
	defer gate.Close()
	_ = gate.SetDeadline(time.Now().Add(4 * time.Second))
	if _, err := io.WriteString(gate, args[1]); err != nil {
		return 70, err
	}
	var permission [1]byte
	if _, err := io.ReadFull(gate, permission[:]); err != nil || permission[0] != 1 {
		return 69, errors.New("launch was not admitted")
	}
	_ = gate.SetDeadline(time.Time{})
	if err := prepareGate(); err != nil {
		return 70, err
	}
	cmd := exec.Command(args[2], args[3:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		return 126, err
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	parentGone := make(chan struct{})
	go func() {
		var buffer [1]byte
		_, _ = gate.Read(buffer[:])
		close(parentGone)
	}()
	select {
	case err := <-exited:
		killGateChildren()
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return exit.ExitCode(), nil
		}
		return 0, err
	case <-parentGone:
		killGateChildren()
		_ = cmd.Process.Kill()
		<-exited
		return 130, nil
	}
}
