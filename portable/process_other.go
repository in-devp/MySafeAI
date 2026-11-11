//go:build !linux && !windows

package main

import "errors"

func openTree(int) (processTree, error) {
	return nil, errors.New("use the native macOS app")
}

func killGateChildren() {}

func prepareGate() error { return nil }
