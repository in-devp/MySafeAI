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
	verify           func(context.Context, config) report
	routes           func(context.Context, string) (bool, error)
	load             func() (config, error)
	path             func(context.Context, config) (connectionPath, error)
	monitorAvailable func() bool
}

func managedChecks(s storage) routeCheck {
	return routeCheck{load: s.load, monitorAvailable: func() bool {
		var beacon watchBeacon
		return s.readJSON(watchBeaconFile, &beacon) == nil && validBeacon(beacon)
	}}
}

func (checks routeCheck) scoped(command []string) routeCheck {
	checks.verify = func(ctx context.Context, c config) report {
		targets := c.commandTargets(command)
		ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
		defer cancel()
		results := make([]chan report, len(targets))
		for index, id := range targets {
			results[index] = make(chan report, 1)
			go func() { results[index] <- verifyTarget(ctx, c, id) }()
		}
		proof := report{Trusted: true, Reason: "trusted route verified"}
		var keys []string
		for _, result := range results {
			item := <-result
			if !item.Trusted {
				return item
			}
			keys = append(keys, item.routeKey)
		}
		proof.routeKey = strings.Join(keys, ":")
		return proof
	}
	checks.path = func(ctx context.Context, c config) (connectionPath, error) {
		var keys []string
		for _, id := range c.commandTargets(command) {
			effective, rule := c.forTarget(id)
			path, err := findConnectionPath(ctx, effective, rule.Mode, id)
			if err != nil {
				return connectionPath{}, err
			}
			keys = append(keys, path.key)
		}
		return connectionPath{key: strings.Join(keys, ":")}, nil
	}
	return checks
}

func (checks routeCheck) samePath(ctx context.Context, c config, proof report) (bool, string) {
	if checks.path != nil {
		path, err := checks.path(ctx, c)
		return err == nil && path.key == proof.routeKey, path.key
	}
	ipv6, err := checks.routes(ctx, c.Adapter)
	return err == nil && ipv6 == proof.IPv6, fmt.Sprint(err == nil, ipv6)
}

func (checks routeCheck) preflight(ctx context.Context, c config) (report, config) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	proof := checks.verify(ctx, c)
	if checks.load == nil || checks.monitorAvailable == nil {
		return proof, c
	}
	key, verifiedAt := policyFingerprint(c), time.Now()
	ticker := time.NewTicker(650 * time.Millisecond)
	defer ticker.Stop()
	for !proof.Trusted && checks.monitorAvailable() {
		select {
		case <-ctx.Done():
			return proof, c
		case <-ticker.C:
		}
		latest, err := checks.load()
		if err != nil {
			continue
		}
		latestKey := policyFingerprint(latest)
		if latestKey != key || time.Since(verifiedAt) >= 5*time.Second {
			c, key = latest, latestKey
			proof, verifiedAt = checks.verify(ctx, c), time.Now()
		}
	}
	return proof, c
}

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
	if checks.load != nil {
		var err error
		if c, err = checks.load(); err != nil {
			return 69, err
		}
		checks = checks.scoped(target)
	}
	proof, c := checks.preflight(ctx, c)
	if !proof.Trusted {
		return 69, errors.New(proof.Reason)
	}
	policyKey := policyFingerprint(c)
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
	samePath, previousPath := checks.samePath(checkCtx, c, proof)
	cancel()
	if !samePath {
		return 69, errors.New("the route changed before launch")
	}
	if checks.load != nil {
		current, err := checks.load()
		if err != nil || policyFingerprint(current) != policyKey {
			return 69, errors.New("the policy changed before launch")
		}
	}
	if _, err := gate.Write([]byte{1}); err != nil {
		return 70, err
	}
	_ = gate.SetDeadline(time.Time{})
	if controller, ok := tree.(interface{ attachGate(net.Conn) }); ok {
		controller.attachGate(gate)
	}
	log(runRunning, "started "+filepath.Base(target[0]))

	routeTick := time.NewTicker(500 * time.Millisecond)
	proofTick := time.NewTicker(5 * time.Second)
	defer routeTick.Stop()
	defer proofTick.Stop()
	recheckCtx, stopChecks := context.WithCancel(ctx)
	defer stopChecks()
	var events <-chan struct{}
	if checks.load != nil {
		events = connectionEvents(recheckCtx)
	}
	results := make(chan report, 1)
	checking := false
	paused := false
	generation := uint64(0)
	var proofGeneration uint64
	lastVerified := time.Now()
	previousWall := lastVerified.UnixNano()
	var pausedSince, closingAt time.Time
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
		case _, open := <-events:
			if !open {
				events = nil
				break
			}
			generation++
			lastVerified = time.Time{}
			if err := tree.update(true); err != nil {
				return 70, fmt.Errorf("process control failed: %w", err)
			}
			if !paused {
				paused, pausedSince = true, time.Now()
				log(runPaused, "paused "+filepath.Base(target[0])+" · network changed")
			}
		case <-routeTick.C:
			wall := time.Now().UnixNano()
			if wall-previousWall > int64(4*time.Second) || wall < previousWall {
				generation++
				lastVerified = time.Time{}
			}
			previousWall = wall
			var policyErr error
			if checks.load != nil {
				var latest config
				if latest, policyErr = checks.load(); policyErr == nil {
					key := policyFingerprint(latest)
					if key != policyKey {
						c, policyKey = latest, key
						generation++
						lastVerified = time.Time{}
					}
				}
			}
			checkCtx, cancel := context.WithTimeout(ctx, time.Second)
			samePath, path := checks.samePath(checkCtx, c, proof)
			cancel()
			if path != previousPath {
				generation++
				previousPath = path
			}
			needsPause := paused || !samePath || policyErr != nil || time.Since(lastVerified) > 12*time.Second
			if err := tree.update(needsPause); err != nil {
				return 70, fmt.Errorf("process control failed: %w", err)
			}
			if needsPause && !paused {
				paused, pausedSince = true, time.Now()
				log(runPaused, "paused "+filepath.Base(target[0])+" · route changed")
			}
			if !closingAt.IsZero() && time.Now().After(closingAt) {
				return 130, errors.New("program closed after VPN timeout")
			}
			if paused && c.CloseAfterDelay && closingAt.IsZero() && time.Since(pausedSince) >= 20*time.Second {
				requestManagedClose(helper.Process.Pid)
				closingAt = time.Now().Add(5 * time.Second)
			}
		case <-proofTick.C:
			if !checking {
				checking = true
				proofGeneration = generation
				go func(snapshot config) { results <- checks.verify(recheckCtx, snapshot) }(c)
			}
		case result := <-results:
			checking = false
			trusted := result.Trusted && proofGeneration == generation && closingAt.IsZero()
			if trusted && checks.load != nil {
				current, err := checks.load()
				trusted = err == nil && policyFingerprint(current) == policyKey
			}
			if trusted {
				checkCtx, cancel := context.WithTimeout(ctx, time.Second)
				trusted, _ = checks.samePath(checkCtx, c, result)
				cancel()
			}
			if trusted {
				proof = result
				lastVerified = time.Now()
			}
			if !trusted && result.Trusted {
				result.Reason = "the route changed during verification"
			}
			if err := tree.update(!trusted); err != nil {
				return 70, fmt.Errorf("process control failed: %w", err)
			}
			if trusted == paused {
				paused = !trusted
				state, action := runRunning, "resumed "
				if paused {
					pausedSince = time.Now()
					state, action = runPaused, "paused "
				}
				log(state, action+filepath.Base(target[0])+" · "+result.Reason)
			}
		}
	}
}

func requestManagedClose(root int) {
	backend := nativeProcessBackend()
	processes, err := backend.list()
	if err != nil {
		return
	}
	for _, process := range processes {
		if process.Parent == root {
			_ = backend.signal(process.Key, appTerminate)
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
		waitForGateClose(gate)
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
