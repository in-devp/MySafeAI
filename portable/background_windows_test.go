package main

import (
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestRegistryLaunchCommandQuotesExecutable(t *testing.T) {
	executable := `C:\Program Files\MySafeAI & Tools\MySafeAI.exe`
	command, err := registryLaunchCommand(executable)
	if err != nil {
		t.Fatal(err)
	}
	args, err := windows.DecomposeCommandLine(command)
	if err != nil || !slices.Equal(args, []string{executable, "background"}) {
		t.Fatalf("registered command parsed as %q, %v", args, err)
	}
	if _, err := registryLaunchCommand(`C:\` + strings.Repeat("a", 260)); err == nil {
		t.Fatal("accepted an oversized Run value")
	}
}

func TestNotificationTextPreservesUTF16(t *testing.T) {
	var buffer [4]uint16
	notificationText(buffer[:], "йц😀")
	if got := windows.UTF16ToString(buffer[:]); got != "йц" {
		t.Fatalf("notification contains a cut surrogate pair: %q", got)
	}
}
