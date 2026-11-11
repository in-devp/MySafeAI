//go:build !linux && !freebsd && !windows

package main

import "context"

func connectionEvents(context.Context) <-chan struct{} { return nil }
