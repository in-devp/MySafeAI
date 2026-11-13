//go:build linux || windows || freebsd

package main

var beginAppProcessBatch func() func()

func nativeProcessBackend() processBackend {
	return processBackend{begin: beginAppProcessBatch, list: listAppProcesses, signal: controlAppProcess, threads: appThreadLeases, adopt: adoptAppThreadLeases}
}
