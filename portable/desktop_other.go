//go:build !linux && !windows && (!freebsd || !cgo)

package main

import (
	"context"
	"errors"
	"runtime"
)

func runDesktop(context.Context, storage, bool) error {
	if runtime.GOOS == "freebsd" {
		return errors.New("the FreeBSD desktop needs a cgo build with GTK4 and WebKitGTK")
	}
	return errors.New("use the native macOS app")
}
