//go:build !windows

package browserbridge

func checkRegistry(registration) error  { return nil }
func writeRegistry(registration) error  { return nil }
func removeRegistry(registration) error { return nil }
