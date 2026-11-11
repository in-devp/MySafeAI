//go:build !linux && !windows

package main

import (
	"context"
	"errors"
)

func runDesktop(context.Context, storage, bool) error {
	return errors.New("use the native macOS app")
}
