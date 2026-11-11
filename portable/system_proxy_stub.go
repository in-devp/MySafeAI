//go:build !windows && ((!linux && !freebsd) || !cgo)

package main

import (
	"context"
	"errors"
	"net/url"
)

func resolveSystemProxy(context.Context, *url.URL) (*url.URL, error) {
	return nil, errors.New("system proxy resolver is unavailable in this build")
}
