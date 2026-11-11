//go:build !windows && !linux && !freebsd

package main

import (
	"context"
	"errors"
)

func loginLaunchEnabled() (bool, error) {
	return false, errors.New("login launch is unavailable on this platform")
}

func setLoginLaunch(bool) error {
	return errors.New("login launch is unavailable on this platform")
}

func notifyProtection(context.Context, string, string) error {
	return errors.New("desktop notifications are unavailable on this platform")
}
