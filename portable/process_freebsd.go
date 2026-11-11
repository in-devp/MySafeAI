package main

import (
	"io"
	"net"
	"os"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// FreeBSD sys/sys/procctl.h and sys/sys/wait.h, stable procctl ABI.
const (
	freeBSDPID     = 0
	reapAcquire    = 2
	reapSignalTree = 6
)

type reaperSignal struct {
	signal  int32
	flags   uint32
	subtree int32
	killed  uint32
	failed  int32
	padding [15]uint32
}

type freeBSDTree struct {
	gate   net.Conn
	paused bool
}

func openTree(int) (processTree, error) { return &freeBSDTree{}, nil }

func (tree *freeBSDTree) attachGate(gate net.Conn) { tree.gate = gate }

// Closing the gate makes the helper kill its own tree. The monitor never sends
// signals to a numeric PID, which could have been reused by another process.
func (tree *freeBSDTree) close() {}

func (tree *freeBSDTree) update(paused bool) error {
	if !paused && !tree.paused {
		return nil
	}
	signal := byte(unix.SIGCONT)
	if paused {
		signal = byte(unix.SIGSTOP)
	}
	if err := tree.gate.SetDeadline(time.Now().Add(time.Second)); err != nil {
		return err
	}
	defer tree.gate.SetDeadline(time.Time{})
	if _, err := tree.gate.Write([]byte{signal}); err != nil {
		return err
	}
	var reply [1]byte
	if _, err := io.ReadFull(tree.gate, reply[:]); err != nil {
		return err
	}
	if reply[0] != 0 {
		return unix.Errno(reply[0])
	}
	tree.paused = paused
	return nil
}

func prepareGate() error {
	_, _, errno := unix.Syscall6(unix.SYS_PROCCTL, freeBSDPID, uintptr(os.Getpid()), reapAcquire, 0, 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func signalGateChildren(signal byte) unix.Errno {
	request := reaperSignal{signal: int32(signal)}
	_, _, errno := unix.Syscall6(unix.SYS_PROCCTL, freeBSDPID, uintptr(os.Getpid()), reapSignalTree,
		uintptr(unsafe.Pointer(&request)), 0, 0)
	if errno == unix.ESRCH {
		return 0
	}
	return errno
}

func waitForGateClose(gate net.Conn) {
	var message [1]byte
	for {
		if _, err := io.ReadFull(gate, message[:]); err != nil {
			return
		}
		if message[0] != byte(unix.SIGSTOP) && message[0] != byte(unix.SIGCONT) {
			return
		}
		reply := byte(signalGateChildren(message[0]))
		if _, err := gate.Write([]byte{reply}); err != nil {
			return
		}
	}
}

func killGateChildren() { _ = signalGateChildren(byte(unix.SIGKILL)) }
