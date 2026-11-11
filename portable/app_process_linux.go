package main

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

var linuxAppBoot = sync.OnceValues(func() (uint64, error) {
	data, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return 0, err
	}
	if len(strings.TrimSpace(string(data))) != 36 {
		return 0, unix.EIO
	}
	digest := sha256.Sum256(data)
	return binary.LittleEndian.Uint64(digest[:]), nil
})

func listAppProcesses() ([]appProcess, error) {
	uid := os.Getuid()
	if uid == 0 || uid != os.Geteuid() {
		return nil, os.ErrPermission
	}
	boot, err := linuxAppBoot()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	var processes []appProcess
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid < 2 {
			continue
		}
		fd, err := openLinuxAppProcess(pid)
		if err != nil {
			continue
		}
		process, err := readLinuxAppProcess(fd, pid, uid, boot)
		if err == nil {
			var executable [8192]byte
			if n, err := unix.Readlinkat(fd, "exe", executable[:]); err == nil && n < len(executable) {
				process.Executable = strings.TrimSuffix(string(executable[:n]), " (deleted)")
			}
			if command, err := readLinuxAppProcessFile(fd, "cmdline", 64<<10); err == nil && len(command) != 0 {
				process.Arguments = strings.Split(strings.TrimSuffix(command, "\x00"), "\x00")
			}
			processes = append(processes, process)
		}
		_ = unix.Close(fd)
	}
	return processes, nil
}

func openLinuxAppProcess(pid int) (int, error) {
	// Linux accepts an open /proc/PID directory as a pidfd for sending signals.
	// Relative lookups and the signal then refer to the same process even if
	// the numeric PID disappears or is reused while we inspect it.
	return unix.Open(filepath.Join("/proc", strconv.Itoa(pid)), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
}

func readLinuxAppProcessFile(dir int, name string, limit int64) (string, error) {
	fd, err := unix.Openat(dir, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return "", err
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if int64(len(data)) > limit {
		return "", unix.E2BIG
	}
	return string(data), err
}

func readLinuxAppProcess(fd, pid, uid int, boot uint64) (appProcess, error) {
	stat, err := readLinuxAppProcessFile(fd, "stat", 4096)
	if err != nil {
		return appProcess{}, err
	}
	end := strings.LastIndexByte(stat, ')')
	if end < 0 {
		return appProcess{}, unix.EIO
	}
	fields := strings.Fields(stat[end+1:])
	if len(fields) < 20 {
		return appProcess{}, unix.EIO
	}
	switch fields[0] {
	case "Z", "X", "x":
		return appProcess{}, os.ErrProcessDone
	}
	parent, parentErr := strconv.Atoi(fields[1])
	birth, birthErr := strconv.ParseUint(fields[19], 10, 64)
	if parentErr != nil || birthErr != nil {
		return appProcess{}, unix.EIO
	}
	status, err := readLinuxAppProcessFile(fd, "status", 64<<10)
	if err != nil {
		return appProcess{}, err
	}
	if !linuxAppProcessOwner(status, strconv.Itoa(uid)) {
		return appProcess{}, os.ErrPermission
	}
	return appProcess{
		Key:     appProcessKey{PID: pid, Started: boot ^ birth},
		Order:   birth,
		Parent:  parent,
		Stopped: fields[0] == "T" || fields[0] == "t",
	}, nil
}

func linuxAppProcessOwner(status, uid string) bool {
	for line := range strings.Lines(status) {
		ids, found := strings.CutPrefix(line, "Uid:")
		if !found {
			continue
		}
		fields := strings.Fields(ids)
		if len(fields) != 4 {
			return false
		}
		// Real, effective, saved and filesystem UIDs must all belong to the user.
		return fields[0] == uid && fields[1] == uid && fields[2] == uid && fields[3] == uid
	}
	return false
}

func controlAppProcess(key appProcessKey, action appProcessAction) error {
	uid := os.Getuid()
	if uid == 0 || uid != os.Geteuid() || key.PID < 2 || key.PID == os.Getpid() {
		return os.ErrPermission
	}
	var signal unix.Signal
	switch action {
	case appPause:
		signal = unix.SIGSTOP
	case appResume:
		signal = unix.SIGCONT
	case appTerminate:
		signal = unix.SIGTERM
	case appKill:
		signal = unix.SIGKILL
	default:
		return unix.EINVAL
	}
	boot, err := linuxAppBoot()
	if err != nil {
		return err
	}
	fd, err := openLinuxAppProcess(key.PID)
	if err != nil {
		return linuxAppProcessError(err)
	}
	defer unix.Close(fd)
	current, err := readLinuxAppProcess(fd, key.PID, uid, boot)
	if err != nil {
		return linuxAppProcessError(err)
	}
	if current.Key != key {
		return os.ErrProcessDone
	}
	if action == appPause && current.Stopped {
		return errAppProcessAlreadyStopped
	}
	return linuxAppProcessError(unix.PidfdSendSignal(fd, signal, nil, 0))
}

func linuxAppProcessError(err error) error {
	if errors.Is(err, unix.ESRCH) || errors.Is(err, os.ErrNotExist) {
		return os.ErrProcessDone
	}
	return err
}
