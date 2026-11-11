//go:build freebsd && cgo

package main

/*
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <sys/user.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

static int app_read_boottime(struct timeval *boot) {
    int mib[] = { CTL_KERN, KERN_BOOTTIME };
    size_t length = sizeof(*boot);
    if (sysctl(mib, 2, boot, &length, NULL, 0) == -1)
        return errno;
    return length == sizeof(*boot) ? 0 : EIO;
}

static int app_read_process(pid_t pid, struct kinfo_proc *process) {
    int mib[] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, pid };
    size_t length = sizeof(*process);
    if (sysctl(mib, 4, process, &length, NULL, 0) == -1)
        return errno;
    if (length == 0)
        return ESRCH;
    if (length != sizeof(*process) || process->ki_structsize != sizeof(*process))
        return EIO;
    return process->ki_pid == pid ? 0 : ESRCH;
}

static int app_user_process(const struct kinfo_proc *p, uid_t uid, int jail) {
    return p->ki_structsize == sizeof(*p) && p->ki_pid > 1 &&
        p->ki_jid == jail && !(p->ki_flag & P_SYSTEM) &&
        p->ki_uid == uid && p->ki_ruid == uid && p->ki_svuid == uid &&
        p->ki_stat != SIDL && p->ki_stat != SZOMB;
}

static uint64_t app_process_birth(const struct kinfo_proc *p, const struct timeval *boot) {
    // ki_start is a wall-clock value and shifts when the boot-time offset
    // changes. Subtract the offset to recover the kernel's monotonic birth.
    struct timeval birth;
    timersub(&p->ki_start, boot, &birth);
    if (birth.tv_sec < 0 || (uint64_t)birth.tv_sec >= UINT64_MAX / 1000000)
        return 0;
    return (uint64_t)birth.tv_sec * 1000000 + birth.tv_usec;
}

static int app_read_processes(uid_t uid, struct kinfo_proc **entries, size_t *count,
                              struct timeval *boot, int *jail) {
    struct kinfo_proc self;
    int status = app_read_process(getpid(), &self);
    if (status != 0)
        return status;
    *jail = self.ki_jid;
    int mib[] = { CTL_KERN, KERN_PROC, KERN_PROC_UID, (int)uid };
    for (int attempt = 0; attempt < 4; attempt++) {
        struct timeval after;
        status = app_read_boottime(boot);
        if (status != 0)
            return status;
        size_t length = 0;
        if (sysctl(mib, 4, NULL, &length, NULL, 0) == -1)
            return errno;
        if (length == 0)
            return 0;
        struct kinfo_proc *buffer = malloc(length);
        if (buffer == NULL)
            return ENOMEM;
        if (sysctl(mib, 4, buffer, &length, NULL, 0) == -1) {
            status = errno;
            free(buffer);
            if (status == ENOMEM)
                continue;
            return status;
        }
        status = app_read_boottime(&after);
        if (status != 0 || length % sizeof(*buffer) != 0) {
            free(buffer);
            return status != 0 ? status : EIO;
        }
        if (timercmp(boot, &after, !=)) {
            free(buffer);
            continue;
        }
        *entries = buffer;
        *count = length / sizeof(*buffer);
        return 0;
    }
    return EAGAIN;
}

static int app_signal_process(pid_t pid, uint64_t birth, int signal_number) {
    uid_t uid = getuid();
    if (uid == 0 || uid != geteuid() || pid <= 1 || pid == getpid())
        return EPERM;
    struct kinfo_proc self, process;
    struct timeval boot, after;
    int status = app_read_process(getpid(), &self);
    if (status == 0)
        status = app_read_boottime(&boot);
    if (status == 0)
        status = app_read_process(pid, &process);
    if (status == 0)
        status = app_read_boottime(&after);
    if (status != 0)
        return status;
    if (timercmp(&boot, &after, !=))
        return EAGAIN;
    if (birth == 0 || process.ki_stat == SZOMB || app_process_birth(&process, &boot) != birth)
        return ESRCH;
    if (!app_user_process(&process, uid, self.ki_jid))
        return EPERM;
    if (signal_number == SIGSTOP && process.ki_stat == SSTOP)
        return EALREADY;

    // FreeBSD 15.1 cannot open a process descriptor for an existing PID.
    // Keep the last identity check and the signal together, with no Go
    // scheduling point or intermediate PID lookup.
    return kill(pid, signal_number) == -1 ? errno : 0;
}
*/
import "C"

import (
	"crypto/sha256"
	"encoding/binary"
	"os"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

var freeBSDAppBoot = sync.OnceValues(func() (uint64, error) {
	data, err := unix.SysctlRaw("kern.boot_id")
	if err != nil {
		return 0, err
	}
	if len(data) != 16 {
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
	boot, err := freeBSDAppBoot()
	if err != nil {
		return nil, err
	}
	var entries *C.struct_kinfo_proc
	var count C.size_t
	var offset C.struct_timeval
	var jail C.int
	if status := C.app_read_processes(C.uid_t(uid), &entries, &count, &offset, &jail); status != 0 {
		return nil, unix.Errno(status)
	}
	defer C.free(unsafe.Pointer(entries))
	records := unsafe.Slice(entries, int(count))
	processes := make([]appProcess, 0, len(records))
	for i := range records {
		entry := &records[i]
		if C.app_user_process(entry, C.uid_t(uid), jail) == 0 {
			continue
		}
		birth := uint64(C.app_process_birth(entry, &offset))
		if birth == 0 {
			continue
		}
		pid := int(entry.ki_pid)
		executable, _ := unix.SysctlArgs("kern.proc.pathname", pid)
		var arguments []string
		if command, err := unix.SysctlArgs("kern.proc.args", pid); err == nil && command != "" && len(command) <= 64<<10 {
			arguments = strings.Split(command, "\x00")
		}
		processes = append(processes, appProcess{
			Key:        appProcessKey{PID: pid, Started: boot ^ birth},
			Parent:     int(entry.ki_ppid),
			Order:      birth,
			Executable: executable,
			Arguments:  arguments,
			Stopped:    entry.ki_stat == C.SSTOP,
		})
	}
	return processes, nil
}

func controlAppProcess(key appProcessKey, action appProcessAction) error {
	pid := C.pid_t(key.PID)
	if int(pid) != key.PID {
		return os.ErrProcessDone
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
	boot, err := freeBSDAppBoot()
	if err != nil {
		return err
	}
	switch status := unix.Errno(C.app_signal_process(pid, C.uint64_t(boot^key.Started), C.int(signal))); status {
	case 0:
		return nil
	case unix.ESRCH, unix.ENOENT:
		return os.ErrProcessDone
	case unix.EALREADY:
		return errAppProcessAlreadyStopped
	default:
		return status
	}
}
