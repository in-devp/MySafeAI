//go:build !freebsd

package main

import "net"

func waitForGateClose(gate net.Conn) {
	var buffer [1]byte
	_, _ = gate.Read(buffer[:])
}
