//go:build !windows

package main

func appThreadLeases(appProcessKey) []appThreadLease { return nil }

func adoptAppThreadLeases(appProcessKey, []appThreadLease) error { return nil }
