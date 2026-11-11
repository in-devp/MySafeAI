//go:build linux || windows || freebsd

package main

func nativeProcessBackend() processBackend {
	return processBackend{list: listAppProcesses, signal: controlAppProcess, threads: appThreadLeases, adopt: adoptAppThreadLeases}
}
