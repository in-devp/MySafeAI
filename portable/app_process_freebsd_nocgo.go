//go:build freebsd && !cgo

package main

import "golang.org/x/sys/unix"

func listAppProcesses() ([]appProcess, error) { return nil, unix.ENOSYS }

func controlAppProcess(appProcessKey, appProcessAction) error { return unix.ENOSYS }
