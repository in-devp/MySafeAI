package main

import (
	"errors"
	"fmt"
	"math"
	"os"
	"runtime"
	"sort"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	appIsProcessCritical = kernel32.NewProc("IsProcessCritical")
	appGetThreadTimes    = kernel32.NewProc("GetThreadTimes")
	appNTDLL             = windows.NewLazySystemDLL("ntdll.dll")
	appQueryProcess      = appNTDLL.NewProc("NtQueryInformationProcess")
	appQueryThread       = appNTDLL.NewProc("NtQueryInformationThread")
	appUser32            = windows.NewLazySystemDLL("user32.dll")
	appWindowOwner       = appUser32.NewProc("GetWindowThreadProcessId")
	appPostMessage       = appUser32.NewProc("PostMessageW")

	appPausesMu sync.Mutex
	appPauses   = make(map[appProcessKey]windowsAppPause)
)

type windowsAppPause struct {
	threads  map[uint32]windowsAppThread
	complete bool
}

type windowsAppThread struct {
	handle    windows.Handle
	lease     appThreadLease
	recovered bool
}

type windowsAppOwner struct {
	user    *windows.SID
	session uint32
}

func windowsAppOwnerForToken(token windows.Token) (windowsAppOwner, error) {
	user, err := token.GetTokenUser()
	if err != nil {
		return windowsAppOwner{}, err
	}
	var session, length uint32
	err = windows.GetTokenInformation(token, windows.TokenSessionId,
		(*byte)(unsafe.Pointer(&session)), uint32(unsafe.Sizeof(session)), &length)
	if err != nil {
		return windowsAppOwner{}, err
	}
	return windowsAppOwner{user: user.User.Sid, session: session}, nil
}

func listAppProcesses() ([]appProcess, error) {
	owner, err := windowsAppOwnerForToken(windows.GetCurrentProcessToken())
	if err != nil {
		return nil, err
	}
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snapshot)

	stopped := windowsAppStopped()
	var processes []appProcess
	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	for err := windows.Process32First(snapshot, &entry); ; err = windows.Process32Next(snapshot, &entry) {
		if errors.Is(err, windows.ERROR_NO_MORE_FILES) {
			return processes, nil
		}
		if err != nil {
			return nil, err
		}
		process, key, err := openWindowsAppProcess(int(entry.ProcessID), 0, owner, 0)
		if err != nil {
			continue
		}
		executable := windowsAppExecutable(process)
		var arguments []string
		var parent int
		if executable != "" {
			arguments = windowsAppArguments(process)
			parent = windowsAppParent(process)
		}
		_ = windows.CloseHandle(process)
		if executable == "" {
			continue
		}
		processes = append(processes, appProcess{
			Key: key, Parent: parent, Order: key.Started, Executable: executable,
			Arguments: arguments, Stopped: stopped[key],
		})
	}
}

func openWindowsAppProcess(pid int, started uint64, owner windowsAppOwner, extraAccess uint32) (windows.Handle, appProcessKey, error) {
	if pid <= 0 || uint64(pid) > math.MaxUint32 {
		return 0, appProcessKey{}, os.ErrProcessDone
	}
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE|extraAccess, false, uint32(pid))
	if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
		return 0, appProcessKey{}, os.ErrProcessDone
	}
	if err != nil {
		return 0, appProcessKey{}, err
	}
	key, err := verifyWindowsAppProcess(process, pid, started, owner)
	if err != nil {
		_ = windows.CloseHandle(process)
		return 0, appProcessKey{}, err
	}
	return process, key, nil
}

func verifyWindowsAppProcess(process windows.Handle, pid int, started uint64, owner windowsAppOwner) (appProcessKey, error) {
	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(process, &creation, &exit, &kernel, &user); err != nil {
		return appProcessKey{}, err
	}
	key := appProcessKey{PID: pid, Started: uint64(creation.HighDateTime)<<32 | uint64(creation.LowDateTime)}
	if key.Started == 0 || started != 0 && key.Started != started {
		return appProcessKey{}, os.ErrProcessDone
	}

	var token windows.Token
	if err := windows.OpenProcessToken(process, windows.TOKEN_QUERY, &token); err != nil {
		return appProcessKey{}, err
	}
	defer token.Close()
	processOwner, err := windowsAppOwnerForToken(token)
	if err != nil {
		return appProcessKey{}, err
	}
	if processOwner.session != owner.session || !processOwner.user.Equals(owner.user) {
		return appProcessKey{}, windows.ERROR_ACCESS_DENIED
	}
	var critical int32
	ok, _, err := appIsProcessCritical.Call(uintptr(process), uintptr(unsafe.Pointer(&critical)))
	if ok == 0 {
		return appProcessKey{}, err
	}
	if critical != 0 {
		return appProcessKey{}, windows.ERROR_ACCESS_DENIED
	}
	if err := windowsAppAlive(process); err != nil {
		return appProcessKey{}, err
	}
	return key, nil
}

func windowsAppAlive(handle windows.Handle) error {
	status, err := windows.WaitForSingleObject(handle, 0)
	if err != nil {
		return err
	}
	switch status {
	case windows.WAIT_OBJECT_0:
		return os.ErrProcessDone
	case uint32(windows.WAIT_TIMEOUT):
		return nil
	default:
		return fmt.Errorf("unexpected process or thread wait status: %d", status)
	}
}

func windowsAppExecutable(process windows.Handle) string {
	for size := uint32(512); size <= 32768; size *= 2 {
		buf := make([]uint16, size)
		length := size
		err := windows.QueryFullProcessImageName(process, 0, &buf[0], &length)
		if err == nil && length <= size {
			return windows.UTF16ToString(buf[:length])
		}
		if !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) {
			return ""
		}
	}
	return ""
}

func windowsAppParent(process windows.Handle) int {
	if appQueryProcess.Find() != nil {
		return 0
	}
	var information windows.PROCESS_BASIC_INFORMATION
	// Read the parent from the process handle. A Toolhelp entry's PID can have
	// been reused before OpenProcess, leaving its snapshot parent unrelated.
	status, _, _ := appQueryProcess.Call(uintptr(process), windows.ProcessBasicInformation,
		uintptr(unsafe.Pointer(&information)), unsafe.Sizeof(information), 0)
	if status != 0 || information.InheritedFromUniqueProcessId > math.MaxUint32 {
		return 0
	}
	return int(information.InheritedFromUniqueProcessId)
}

func windowsAppArguments(process windows.Handle) []string {
	// The public GetCommandLine API can only query the current process.
	// Other processes' command lines are optional and Windows may refuse access.
	if appQueryProcess.Find() != nil {
		return nil
	}
	var size uint32
	status, _, _ := appQueryProcess.Call(uintptr(process), windows.ProcessCommandLineInformation, 0, 0,
		uintptr(unsafe.Pointer(&size)))
	if windows.NTStatus(status) != windows.STATUS_INFO_LENGTH_MISMATCH &&
		windows.NTStatus(status) != windows.STATUS_BUFFER_TOO_SMALL {
		return nil
	}
	headerSize := unsafe.Sizeof(windows.NTUnicodeString{})
	if uintptr(size) < headerSize || size > 128*1024 {
		return nil
	}
	buffer := make([]byte, size)
	base := unsafe.Pointer(&buffer[0])
	var length uint32
	status, _, _ = appQueryProcess.Call(uintptr(process), windows.ProcessCommandLineInformation, uintptr(base),
		uintptr(size), uintptr(unsafe.Pointer(&length)))
	if status != 0 || uintptr(length) < headerSize || length > size {
		return nil
	}
	header := (*windows.NTUnicodeString)(base)
	start, address := uintptr(base), uintptr(unsafe.Pointer(header.Buffer))
	if address < start+headerSize || address > start+uintptr(length) || address%2 != 0 ||
		header.Length%2 != 0 || header.Length > header.MaximumLength || uintptr(header.Length) > start+uintptr(length)-address {
		return nil
	}
	text := windows.UTF16ToString(unsafe.Slice((*uint16)(unsafe.Add(base, address-start)), int(header.Length)/2))
	if text == "" {
		return nil
	}
	args, _ := windows.DecomposeCommandLine(text)
	return args
}

func controlAppProcess(key appProcessKey, action appProcessAction) error {
	if key.PID == os.Getpid() || key.Started == 0 {
		return os.ErrProcessDone
	}
	owner, err := windowsAppOwnerForToken(windows.GetCurrentProcessToken())
	if err != nil {
		return err
	}
	access := uint32(0)
	if action == appKill {
		access = windows.PROCESS_TERMINATE
	}
	appPausesMu.Lock()
	defer appPausesMu.Unlock()

	process, _, err := openWindowsAppProcess(key.PID, key.Started, owner, access)
	if errors.Is(err, os.ErrProcessDone) {
		closeWindowsAppThreads(appPauses[key].threads)
		delete(appPauses, key)
	}
	if err != nil {
		return err
	}
	defer windows.CloseHandle(process)
	switch action {
	case appPause:
		return pauseWindowsApp(process, key)
	case appResume:
		pause := appPauses[key]
		if err := resumeWindowsAppThreads(pause.threads); err != nil {
			pause.complete = false
			appPauses[key] = pause
			return err
		}
		delete(appPauses, key)
		return nil
	case appTerminate:
		return closeWindowsAppWindows(process, uint32(key.PID))
	case appKill:
		err := windows.TerminateProcess(process, 1)
		if err != nil && errors.Is(windowsAppAlive(process), os.ErrProcessDone) {
			return os.ErrProcessDone
		}
		return err
	default:
		return fmt.Errorf("unknown application process action: %d", action)
	}
}

func windowsAppStopped() map[appProcessKey]bool {
	appPausesMu.Lock()
	defer appPausesMu.Unlock()
	stopped := make(map[appProcessKey]bool, len(appPauses))
	for key, pause := range appPauses {
		for id, thread := range pause.threads {
			if errors.Is(windowsAppAlive(thread.handle), os.ErrProcessDone) {
				_ = windows.CloseHandle(thread.handle)
				delete(pause.threads, id)
			}
		}
		if len(pause.threads) == 0 {
			delete(appPauses, key)
		} else {
			stopped[key] = pause.complete
		}
	}
	return stopped
}

func pauseWindowsApp(process windows.Handle, key appProcessKey) error {
	pause := appPauses[key]
	if pause.threads == nil {
		pause.threads = make(map[uint32]windowsAppThread)
	}
	newThreads := make(map[uint32]windowsAppThread)
	err := suspendWindowsAppThreads(process, uint32(key.PID), pause.threads, newThreads)
	if err == nil && len(pause.threads)+len(newThreads) == 0 {
		err = windowsAppAlive(process)
		if err == nil {
			err = errors.New("the process had no suspendable threads in the snapshot")
		}
	}
	if err != nil {
		// Avoid leaving an incomplete new pause behind on a failed request.
		// A handle whose rollback failed stays owned for a later release attempt.
		err = errors.Join(err, resumeWindowsAppThreads(newThreads))
	}
	for id, thread := range newThreads {
		pause.threads[id] = thread
	}
	pause.complete = err == nil
	if len(pause.threads) != 0 {
		appPauses[key] = pause
	}
	return err
}

func suspendWindowsAppThreads(process windows.Handle, pid uint32, owned, added map[uint32]windowsAppThread) error {
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
		if entry.OwnerProcessID != pid {
			continue
		}
		if thread, ok := owned[entry.ThreadID]; ok {
			if !errors.Is(windowsAppAlive(thread.handle), os.ErrProcessDone) {
				continue
			}
			_ = windows.CloseHandle(thread.handle)
			delete(owned, entry.ThreadID)
		}

		thread, err := openWindowsAppThread(pid, entry.ThreadID)
		if errors.Is(err, os.ErrProcessDone) {
			continue
		}
		if err != nil {
			return err
		}
		if err := windowsAppAlive(process); err != nil {
			_ = windows.CloseHandle(thread.handle)
			return err
		}
		count, _, err := suspendThread.Call(uintptr(thread.handle))
		if uint32(count) == math.MaxUint32 {
			dead := errors.Is(windowsAppAlive(thread.handle), os.ErrProcessDone)
			_ = windows.CloseHandle(thread.handle)
			if dead {
				continue
			}
			return fmt.Errorf("SuspendThread: %w", err)
		}
		// Record one increment, including when another caller already holds a pause.
		thread.lease.Count = uint32(count) + 1
		added[entry.ThreadID] = thread
	}
}

func openWindowsAppThread(pid, id uint32) (windowsAppThread, error) {
	thread, err := windows.OpenThread(windows.THREAD_SUSPEND_RESUME|windows.THREAD_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE,
		false, id)
	if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
		return windowsAppThread{}, os.ErrProcessDone
	}
	if err != nil {
		return windowsAppThread{}, err
	}
	owner, _, _ := threadOwner.Call(uintptr(thread))
	if owner != uintptr(pid) {
		_ = windows.CloseHandle(thread)
		return windowsAppThread{}, os.ErrProcessDone
	}
	if err := windowsAppAlive(thread); err != nil {
		_ = windows.CloseHandle(thread)
		return windowsAppThread{}, err
	}
	var creation, exit, kernel, user windows.Filetime
	ok, _, err := appGetThreadTimes.Call(uintptr(thread),
		uintptr(unsafe.Pointer(&creation)), uintptr(unsafe.Pointer(&exit)),
		uintptr(unsafe.Pointer(&kernel)), uintptr(unsafe.Pointer(&user)))
	if ok == 0 {
		if errors.Is(windowsAppAlive(thread), os.ErrProcessDone) {
			err = os.ErrProcessDone
		}
		_ = windows.CloseHandle(thread)
		return windowsAppThread{}, err
	}
	started := uint64(creation.HighDateTime)<<32 | uint64(creation.LowDateTime)
	if started == 0 {
		_ = windows.CloseHandle(thread)
		return windowsAppThread{}, errors.New("the thread has no creation time")
	}
	return windowsAppThread{handle: thread, lease: appThreadLease{ID: id, Started: started}}, nil
}

func closeWindowsAppThreads(threads map[uint32]windowsAppThread) {
	for _, thread := range threads {
		_ = windows.CloseHandle(thread.handle)
	}
}

func windowsAppThreadSuspendCount(thread windows.Handle) (uint32, error) {
	if err := appQueryThread.Find(); err != nil {
		return 0, err
	}
	// ThreadSuspendCount (Windows 8.1+) reads the count without changing it.
	// Win32 SuspendThread/ResumeThread cannot provide a read-only probe.
	const threadSuspendCount = 35
	var count uint32
	status, _, _ := appQueryThread.Call(uintptr(thread), threadSuspendCount,
		uintptr(unsafe.Pointer(&count)), unsafe.Sizeof(count), 0)
	if status != 0 {
		return 0, windows.NTStatus(status)
	}
	return count, nil
}

func appThreadLeases(key appProcessKey) []appThreadLease {
	appPausesMu.Lock()
	defer appPausesMu.Unlock()
	threads := appPauses[key].threads
	if len(threads) == 0 {
		return nil
	}
	leases := make([]appThreadLease, 0, len(threads))
	for _, thread := range threads {
		if !errors.Is(windowsAppAlive(thread.handle), os.ErrProcessDone) {
			leases = append(leases, thread.lease)
		}
	}
	sort.Slice(leases, func(i, j int) bool { return leases[i].ID < leases[j].ID })
	return leases
}

func adoptAppThreadLeases(key appProcessKey, leases []appThreadLease) error {
	if key.PID == os.Getpid() || key.Started == 0 {
		return os.ErrProcessDone
	}
	if len(leases) == 0 {
		return errors.New("no Windows thread suspensions to recover")
	}
	owner, err := windowsAppOwnerForToken(windows.GetCurrentProcessToken())
	if err != nil {
		return err
	}
	appPausesMu.Lock()
	defer appPausesMu.Unlock()
	process, _, err := openWindowsAppProcess(key.PID, key.Started, owner, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(process)

	pause := appPauses[key]
	recovered := make(map[uint32]windowsAppThread)
	defer closeWindowsAppThreads(recovered)
	seen := make(map[uint32]bool, len(leases))
	for _, lease := range leases {
		if lease.ID == 0 || lease.Started == 0 || lease.Count == 0 || seen[lease.ID] {
			return errors.New("invalid or repeated Windows thread suspension record")
		}
		seen[lease.ID] = true
		if thread, ok := pause.threads[lease.ID]; ok && !errors.Is(windowsAppAlive(thread.handle), os.ErrProcessDone) {
			if thread.lease != lease {
				return fmt.Errorf("conflicting Windows thread suspension record for thread %d", lease.ID)
			}
			if err := checkWindowsAppThreadCount(thread.handle, lease.Count); err != nil {
				return fmt.Errorf("recover thread %d: %w", lease.ID, err)
			}
			continue
		}
		thread, err := reopenWindowsAppThread(uint32(key.PID), lease)
		if errors.Is(err, os.ErrProcessDone) {
			continue
		}
		if err != nil {
			return fmt.Errorf("recover thread %d: %w", lease.ID, err)
		}
		recovered[lease.ID] = thread
	}
	if err := windowsAppAlive(process); err != nil {
		return err
	}
	if len(recovered) != 0 {
		if pause.threads == nil {
			pause.threads = make(map[uint32]windowsAppThread, len(recovered))
		}
		for id, thread := range recovered {
			if previous, ok := pause.threads[id]; ok {
				_ = windows.CloseHandle(previous.handle)
			}
			pause.threads[id] = thread
			delete(recovered, id)
		}
		// The old snapshot says nothing about threads created afterwards.
		pause.complete = false
		appPauses[key] = pause
	}
	return nil
}

func reopenWindowsAppThread(pid uint32, lease appThreadLease) (windowsAppThread, error) {
	thread, err := openWindowsAppThread(pid, lease.ID)
	if err != nil {
		return windowsAppThread{}, err
	}
	if thread.lease.Started != lease.Started {
		_ = windows.CloseHandle(thread.handle)
		return windowsAppThread{}, os.ErrProcessDone
	}
	if err := checkWindowsAppThreadCount(thread.handle, lease.Count); err != nil {
		_ = windows.CloseHandle(thread.handle)
		return windowsAppThread{}, err
	}
	thread.lease = lease
	thread.recovered = true
	return thread, nil
}

func checkWindowsAppThreadCount(thread windows.Handle, expected uint32) error {
	count, err := windowsAppThreadSuspendCount(thread)
	if aliveErr := windowsAppAlive(thread); aliveErr != nil {
		return aliveErr
	}
	if err != nil {
		return err
	}
	if count == 0 {
		return os.ErrProcessDone
	}
	if count != expected {
		return errors.New("suspend count differs from the recorded count")
	}
	return nil
}

func resumeWindowsAppThreads(threads map[uint32]windowsAppThread) error {
	var resumeError error
	for id, thread := range threads {
		released, err := resumeWindowsAppThread(thread)
		if released {
			_ = windows.CloseHandle(thread.handle)
			delete(threads, id)
		}
		if err != nil && !errors.Is(err, os.ErrProcessDone) {
			resumeError = errors.Join(resumeError, fmt.Errorf("resume thread %d: %w", id, err))
		}
	}
	return resumeError
}

func resumeWindowsAppThread(thread windowsAppThread) (bool, error) {
	if err := windowsAppAlive(thread.handle); err != nil {
		return errors.Is(err, os.ErrProcessDone), err
	}
	if thread.recovered {
		if err := checkWindowsAppThreadCount(thread.handle, thread.lease.Count); err != nil {
			return errors.Is(err, os.ErrProcessDone), err
		}
	}
	previous, err := windows.ResumeThread(thread.handle)
	if err != nil {
		if errors.Is(windowsAppAlive(thread.handle), os.ErrProcessDone) {
			return true, nil
		}
		return false, err
	}
	if thread.recovered && previous != 0 && previous != thread.lease.Count {
		// The kernel has no compare-and-resume operation. Restore the increment
		// if a different controller changed the count between query and release.
		failure := errors.New("suspend count changed during release")
		restored, _, err := suspendThread.Call(uintptr(thread.handle))
		if uint32(restored) == math.MaxUint32 {
			// The decrement already happened. Do not attempt a second one later.
			return true, errors.Join(failure, fmt.Errorf("restore suspend count: %w", err))
		}
		return false, failure
	}
	return true, nil
}

type windowsAppCloseRequest struct {
	process windows.Handle
	pid     uint32
	posted  bool
	err     error
}

var appCloseWindowCallback = windows.NewCallback(func(hwnd windows.HWND, data unsafe.Pointer) uintptr {
	request := (*windowsAppCloseRequest)(data)
	var owner uint32
	appWindowOwner.Call(uintptr(hwnd), uintptr(unsafe.Pointer(&owner)))
	if owner != request.pid || !windows.IsWindowVisible(hwnd) {
		return 1
	}
	if err := windowsAppAlive(request.process); err != nil {
		request.err = err
		return 1
	}
	owner = 0
	appWindowOwner.Call(uintptr(hwnd), uintptr(unsafe.Pointer(&owner)))
	if owner == request.pid {
		const wmClose = 0x0010
		ok, _, err := appPostMessage.Call(uintptr(hwnd), wmClose, 0, 0)
		if ok != 0 {
			request.posted = true
		} else if request.err == nil {
			request.err = err
		}
	}
	return 1
})

func closeWindowsAppWindows(process windows.Handle, pid uint32) error {
	request := windowsAppCloseRequest{process: process, pid: pid}
	err := windows.EnumWindows(appCloseWindowCallback, unsafe.Pointer(&request))
	runtime.KeepAlive(&request)
	if err != nil {
		return err
	}
	if request.posted {
		return nil
	}
	if request.err != nil {
		return request.err
	}
	// Sending Ctrl+C to an arbitrary console process can affect unrelated programs.
	return errors.New("the application has no visible window for a close request")
}
