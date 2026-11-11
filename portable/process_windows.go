package main

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32       = windows.NewLazySystemDLL("kernel32.dll")
	suspendThread  = kernel32.NewProc("SuspendThread")
	threadOwner    = kernel32.NewProc("GetProcessIdOfThread")
	isProcessInJob = kernel32.NewProc("IsProcessInJob")
	setJobInfo     = kernel32.NewProc("SetInformationJobObject")
	queryJobInfo   = kernel32.NewProc("QueryInformationJobObject")
)

type windowsTree struct {
	root  uint32
	job   windows.Handle
	owned map[uint32]windows.Handle
}

func openTree(pid int) (processTree, error) {
	process, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(process)
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, err
	}
	var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if ok, _, err := setJobInfo.Call(uintptr(job), windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), unsafe.Sizeof(info)); ok == 0 {
		windows.CloseHandle(job)
		return nil, err
	}
	if err := windows.AssignProcessToJobObject(job, process); err != nil {
		windows.CloseHandle(job)
		return nil, err
	}
	return &windowsTree{uint32(pid), job, make(map[uint32]windows.Handle)}, nil
}

func (t *windowsTree) processes() (map[uint32]windows.Handle, error) {
	type listHeader struct{ assigned, listed uint32 }
	for capacity := 64; capacity <= 16384; capacity *= 2 {
		var header listHeader
		size := int(unsafe.Sizeof(header)) + capacity*int(unsafe.Sizeof(uintptr(0)))
		data := make([]byte, size)
		base := unsafe.Pointer(&data[0])
		ok, _, err := queryJobInfo.Call(uintptr(t.job), windows.JobObjectBasicProcessIdList,
			uintptr(base), uintptr(size), 0)
		if ok == 0 && errors.Is(err, windows.ERROR_MORE_DATA) {
			continue
		}
		if ok == 0 {
			return nil, err
		}
		header = *(*listHeader)(base)
		if header.listed > uint32(capacity) {
			return nil, errors.New("invalid process list size")
		}
		ids := unsafe.Slice((*uintptr)(unsafe.Add(base, unsafe.Sizeof(header))), header.listed)
		processes := make(map[uint32]windows.Handle)
		for _, id := range ids {
			pid := uint32(id)
			if pid == t.root {
				continue
			}
			process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, pid)
			if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
				continue
			}
			if err != nil {
				closeHandles(processes)
				return nil, err
			}
			var member int32
			ok, _, err := isProcessInJob.Call(uintptr(process), uintptr(t.job), uintptr(unsafe.Pointer(&member)))
			if ok == 0 {
				windows.CloseHandle(process)
				closeHandles(processes)
				return nil, err
			}
			if member == 0 {
				windows.CloseHandle(process)
				continue
			}
			processes[pid] = process
		}
		return processes, nil
	}
	return nil, errors.New("too many processes in command job")
}

func closeHandles(handles map[uint32]windows.Handle) {
	for _, handle := range handles {
		windows.CloseHandle(handle)
	}
}

func (t *windowsTree) update(paused bool) error {
	if !paused {
		for id, handle := range t.owned {
			if result, _ := windows.WaitForSingleObject(handle, 0); result == uint32(windows.WAIT_TIMEOUT) {
				if _, err := windows.ResumeThread(handle); err != nil {
					return err
				}
			}
			windows.CloseHandle(handle)
			delete(t.owned, id)
		}
		return nil
	}
	processes, err := t.processes()
	if err != nil {
		return err
	}
	defer closeHandles(processes)
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(snapshot)
	var entry windows.ThreadEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	for err := windows.Thread32First(snapshot, &entry); ; err = windows.Thread32Next(snapshot, &entry) {
		if errors.Is(err, windows.ERROR_NO_MORE_FILES) {
			return nil
		}
		if err != nil {
			return err
		}
		process, ok := processes[entry.OwnerProcessID]
		if !ok {
			continue
		}
		if handle, owned := t.owned[entry.ThreadID]; owned {
			if result, _ := windows.WaitForSingleObject(handle, 0); result == uint32(windows.WAIT_TIMEOUT) {
				continue
			}
			windows.CloseHandle(handle)
			delete(t.owned, entry.ThreadID)
		}
		handle, err := windows.OpenThread(windows.THREAD_SUSPEND_RESUME|windows.THREAD_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, entry.ThreadID)
		if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
			continue
		}
		if err != nil {
			return err
		}
		owner, _, _ := threadOwner.Call(uintptr(handle))
		active, _ := windows.WaitForSingleObject(process, 0)
		if owner != uintptr(entry.OwnerProcessID) || active != uint32(windows.WAIT_TIMEOUT) {
			windows.CloseHandle(handle)
			continue
		}
		result, _, err := suspendThread.Call(uintptr(handle))
		if uint32(result) == ^uint32(0) {
			active, _ := windows.WaitForSingleObject(handle, 0)
			windows.CloseHandle(handle)
			if active == windows.WAIT_OBJECT_0 {
				continue
			}
			return fmt.Errorf("SuspendThread: %w", err)
		}
		t.owned[entry.ThreadID] = handle
	}
}

func (t *windowsTree) close() {
	windows.CloseHandle(t.job)
	closeHandles(t.owned)
}

func prepareGate() error { return nil }
func killGateChildren()  {}
