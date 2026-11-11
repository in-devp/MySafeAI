//go:build !linux && !windows

package main

import "context"

func startTray(context.Context, string, context.CancelFunc) {}
