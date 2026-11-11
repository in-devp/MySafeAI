//go:build linux || windows || freebsd

package main

func nativeProcessBackend() processBackend {
	return processBackend{listAppProcesses, controlAppProcess}
}
