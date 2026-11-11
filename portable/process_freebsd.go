package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"sort"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// FreeBSD sys/sys/procctl.h and sys/sys/wait.h, stable procctl ABI.
const (
	freeBSDPID     = 0
	reapAcquire    = 2
	reapStatus     = 4
	reapGetPIDs    = 5
	reapSignalTree = 6

	reapStatusOwned = 0x01
	reapPIDValid    = 0x01
	reapPIDZombie   = 0x08
	reapPIDExiting  = 0x20
)

type reaperSignal struct {
	signal  int32
	flags   uint32
	subtree int32
	killed  uint32
	failed  int32
	padding [15]uint32
}

type reaperStatus struct {
	flags       uint32
	children    uint32
	descendants uint32
	pid         int32
	first       int32
	padding     [15]uint32
}

type reaperPIDInfo struct {
	pid     int32
	subtree int32
	flags   uint32
	padding [15]uint32
}

type reaperPIDRequest struct {
	count   uint32
	padding [15]uint32
	entries *reaperPIDInfo
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
	if _, err := listAppProcesses(); err != nil {
		return fmt.Errorf("managed process identities unavailable: %w", err)
	}
	_, _, errno := unix.Syscall6(unix.SYS_PROCCTL, freeBSDPID, uintptr(os.Getpid()), reapAcquire, 0, 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func gateReaperMembers() (map[int]bool, error) {
	pid := os.Getpid()
	var status reaperStatus
	_, _, errno := unix.Syscall6(unix.SYS_PROCCTL, freeBSDPID, uintptr(pid), reapStatus,
		uintptr(unsafe.Pointer(&status)), 0, 0)
	if errno != 0 {
		return nil, errno
	}
	if status.flags&reapStatusOwned == 0 || int(status.pid) != pid {
		return nil, unix.EPERM
	}

	// GETPIDS doesn't return the number written. The first unused entry
	// remains zero. If the snapshot fills the buffer, retry with more room
	// because the command might have forked since the status request.
	const maxEntries = 1 << 20
	for capacity := int(status.descendants) + 16; capacity <= maxEntries; capacity = min(capacity*2, maxEntries) {
		entries := make([]reaperPIDInfo, capacity)
		request := reaperPIDRequest{count: uint32(capacity), entries: &entries[0]}
		_, _, errno := unix.Syscall6(unix.SYS_PROCCTL, freeBSDPID, uintptr(pid), reapGetPIDs,
			uintptr(unsafe.Pointer(&request)), 0, 0)
		runtime.KeepAlive(entries)
		if errno != 0 {
			return nil, errno
		}
		if entries[capacity-1].flags&reapPIDValid != 0 {
			if capacity == maxEntries {
				break
			}
			continue
		}
		members := make(map[int]bool)
		for _, entry := range entries {
			if entry.flags&reapPIDValid == 0 {
				break
			}
			if entry.pid > 1 && int(entry.pid) != pid && entry.flags&(reapPIDZombie|reapPIDExiting) == 0 {
				members[int(entry.pid)] = true
			}
		}
		return members, nil
	}
	return nil, unix.EOVERFLOW
}

type gateDescendant struct {
	appProcess
	depth int
}

func gateDescendants(processes []appProcess, members map[int]bool, root int) []gateDescendant {
	byPID := make(map[int]appProcess, len(processes))
	for _, process := range processes {
		if process.Key.PID > 1 && process.Key.PID != root {
			byPID[process.Key.PID] = process
		}
	}

	// The kernel's reaper list includes orphaned descendants, but it
	// omits the children of subordinate reapers. Follow real-parent
	// links only when they lead back to a kernel-confirmed member.
	depths := make(map[int]int, len(byPID))
	visiting := make(map[int]bool)
	var depthFor func(appProcess) int
	depthFor = func(process appProcess) int {
		pid := process.Key.PID
		if pid == 0 || visiting[pid] {
			return 0
		}
		if depth, found := depths[pid]; found {
			return depth
		}
		visiting[pid] = true
		depth := 0
		parent := byPID[process.Parent]
		if parent.Order <= process.Order {
			if parentDepth := depthFor(parent); parentDepth > 0 {
				depth = parentDepth + 1
			}
		}
		if depth == 0 && members[pid] {
			depth = 1
		}
		delete(visiting, pid)
		depths[pid] = depth
		return depth
	}

	var descendants []gateDescendant
	for _, process := range byPID {
		if depth := depthFor(process); depth > 0 {
			descendants = append(descendants, gateDescendant{appProcess: process, depth: depth})
		}
	}
	sort.Slice(descendants, func(i, j int) bool {
		left, right := descendants[i], descendants[j]
		if left.depth != right.depth {
			return left.depth < right.depth
		}
		if left.Order != right.Order {
			return left.Order < right.Order
		}
		return left.Key.PID < right.Key.PID
	})
	return descendants
}

func updateGateDescendants(owned map[appProcessKey]bool, paused bool) error {
	processes, err := listAppProcesses()
	if err != nil {
		return err
	}
	members, err := gateReaperMembers()
	if err != nil {
		return err
	}
	descendants := gateDescendants(processes, members, os.Getpid())
	present := make(map[appProcessKey]bool, len(descendants))
	for _, descendant := range descendants {
		present[descendant.Key] = true
	}
	for key := range owned {
		if !present[key] {
			delete(owned, key)
		}
	}
	if paused {
		for _, descendant := range descendants {
			if descendant.Stopped {
				continue
			}
			key := descendant.Key
			switch err := controlAppProcess(key, appPause); {
			case err == nil:
				owned[key] = true
			case errors.Is(err, os.ErrProcessDone), errors.Is(err, errAppProcessAlreadyStopped):
				delete(owned, key)
			default:
				return err
			}
		}
		return nil
	}
	for i := len(descendants) - 1; i >= 0; i-- {
		descendant := descendants[i]
		if !owned[descendant.Key] {
			continue
		}
		if descendant.Stopped {
			err := controlAppProcess(descendant.Key, appResume)
			if err != nil && !errors.Is(err, os.ErrProcessDone) {
				return err
			}
		}
		delete(owned, descendant.Key)
	}
	return nil
}

func gateResponse(err error) byte {
	if err == nil {
		return 0
	}
	var errno unix.Errno
	if errors.As(err, &errno) && errno < 256 {
		return byte(errno)
	}
	if errors.Is(err, os.ErrPermission) {
		return byte(unix.EPERM)
	}
	return byte(unix.EIO)
}

func waitForGateClose(gate net.Conn) {
	owned := make(map[appProcessKey]bool)
	var message [1]byte
	for {
		if _, err := io.ReadFull(gate, message[:]); err != nil {
			return
		}
		if message[0] != byte(unix.SIGSTOP) && message[0] != byte(unix.SIGCONT) {
			return
		}
		reply := gateResponse(updateGateDescendants(owned, message[0] == byte(unix.SIGSTOP)))
		if _, err := gate.Write([]byte{reply}); err != nil {
			return
		}
	}
}

func killGateChildren() {
	request := reaperSignal{signal: int32(unix.SIGKILL)}
	_, _, _ = unix.Syscall6(unix.SYS_PROCCTL, freeBSDPID, uintptr(os.Getpid()), reapSignalTree,
		uintptr(unsafe.Pointer(&request)), 0, 0)
}
