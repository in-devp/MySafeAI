//go:build linux || freebsd || windows

package main

import (
	"context"
	"testing"
	"time"
)

func TestConnectionEventsClosesOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events := connectionEvents(ctx)
	if events == nil {
		t.Skip("native network notifications unavailable")
	}
	cancel()
	timer := time.NewTimer(3 * time.Second)
	defer timer.Stop()
	for {
		select {
		case _, open := <-events:
			if !open {
				return
			}
		case <-timer.C:
			t.Fatal("native network notifications did not close")
		}
	}
}
