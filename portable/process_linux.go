package main

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

type linuxProcess struct {
	pid, parent int
	birth       string
	state       string
}

type ownedProcess struct {
	birth string
	fd    int
}

type linuxTree struct {
	root  int
	birth string
	known map[int]linuxProcess
	owned map[int]ownedProcess
}

func openTree(pid int) (processTree, error) {
	fd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return nil, err
	}
	unix.Close(fd)
	p, ok := readProcess(pid)
	if !ok {
		return nil, unix.ESRCH
	}
	return &linuxTree{root: pid, birth: p.birth, known: make(map[int]linuxProcess), owned: make(map[int]ownedProcess)}, nil
}

func readProcess(pid int) (linuxProcess, bool) {
	file := filepath.Join("/proc", strconv.Itoa(pid), "stat")
	data, err := os.ReadFile(file)
	if err != nil {
		return linuxProcess{}, false
	}
	body := string(data)
	end := strings.LastIndexByte(body, ')')
	if end < 0 {
		return linuxProcess{}, false
	}
	fields := strings.Fields(body[end+1:])
	if len(fields) < 20 {
		return linuxProcess{}, false
	}
	parent, err := strconv.Atoi(fields[1])
	return linuxProcess{pid, parent, fields[19], fields[0]}, err == nil
}

func (t *linuxTree) refresh() ([]linuxProcess, error) {
	dirs, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	children := make(map[int][]linuxProcess)
	active := make(map[int]linuxProcess)
	for _, dir := range dirs {
		pid, err := strconv.Atoi(dir.Name())
		if err != nil {
			continue
		}
		if p, ok := readProcess(pid); ok && p.state != "Z" {
			active[pid] = p
			children[p.parent] = append(children[p.parent], p)
		}
	}
	var queue []int
	if root, ok := active[t.root]; ok && root.birth == t.birth {
		queue = append(queue, t.root)
	}
	for pid, previous := range t.known {
		if current, ok := active[pid]; ok && current.birth == previous.birth {
			queue = append(queue, pid)
		}
	}
	t.known = make(map[int]linuxProcess)
	visited := map[int]bool{t.root: true}
	var found []linuxProcess
	for i := 0; i < len(queue); i++ {
		pid := queue[i]
		if !visited[pid] {
			visited[pid] = true
			found = append(found, active[pid])
			t.known[pid] = active[pid]
		}
		for _, child := range children[pid] {
			if !visited[child.pid] {
				visited[child.pid] = true
				found = append(found, child)
				t.known[child.pid] = child
				queue = append(queue, child.pid)
			}
		}
	}
	return found, nil
}

func signalProcess(p linuxProcess, signal unix.Signal) (int, error) {
	fd, err := unix.PidfdOpen(p.pid, 0)
	if errors.Is(err, unix.ESRCH) {
		return -1, nil
	}
	if err != nil {
		return -1, err
	}
	if current, ok := readProcess(p.pid); !ok || current.birth != p.birth {
		unix.Close(fd)
		return -1, nil
	}
	if err := unix.PidfdSendSignal(fd, signal, nil, 0); err != nil {
		unix.Close(fd)
		if errors.Is(err, unix.ESRCH) {
			return -1, nil
		}
		return -1, err
	}
	return fd, nil
}

func (t *linuxTree) update(paused bool) error {
	processes, err := t.refresh()
	if err != nil {
		return err
	}
	for pid, process := range t.owned {
		if current, alive := t.known[pid]; !alive || current.birth != process.birth {
			unix.Close(process.fd)
			delete(t.owned, pid)
		}
	}
	if paused {
		for _, p := range processes {
			if process, owned := t.owned[p.pid]; owned {
				if p.state != "T" && p.state != "t" {
					if err := unix.PidfdSendSignal(process.fd, unix.SIGSTOP, nil, 0); err != nil && !errors.Is(err, unix.ESRCH) {
						return err
					}
				}
				continue
			}
			if p.state == "T" || p.state == "t" {
				continue
			}
			fd, err := signalProcess(p, unix.SIGSTOP)
			if err != nil {
				return err
			}
			if fd >= 0 {
				t.owned[p.pid] = ownedProcess{p.birth, fd}
			}
		}
		return nil
	}
	for i := len(processes) - 1; i >= 0; i-- {
		pid := processes[i].pid
		if process, ok := t.owned[pid]; ok {
			if err := unix.PidfdSendSignal(process.fd, unix.SIGCONT, nil, 0); err != nil && !errors.Is(err, unix.ESRCH) {
				return err
			}
			unix.Close(process.fd)
			delete(t.owned, pid)
		}
	}
	return nil
}

func (t *linuxTree) close() {
	processes, _ := t.refresh()
	for i := len(processes) - 1; i >= 0; i-- {
		fd, _ := signalProcess(processes[i], unix.SIGKILL)
		if fd >= 0 {
			unix.Close(fd)
		}
	}
	for _, process := range t.owned {
		_ = unix.PidfdSendSignal(process.fd, unix.SIGKILL, nil, 0)
		unix.Close(process.fd)
	}
}

func killGateChildren() {
	p, ok := readProcess(os.Getpid())
	if !ok {
		return
	}
	t := linuxTree{root: p.pid, birth: p.birth}
	t.close()
}

func prepareGate() error {
	return unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0)
}
