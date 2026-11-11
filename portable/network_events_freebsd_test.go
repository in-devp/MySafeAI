package main

import (
	"encoding/binary"
	"testing"

	"golang.org/x/sys/unix"
)

func TestFreeBSDNetworkChangesExcludeRouteLookups(t *testing.T) {
	message := func(kind byte) []byte {
		data := []byte{0, 0, unix.RTM_VERSION, kind}
		binary.NativeEndian.PutUint16(data, uint16(len(data)))
		return data
	}
	lookups := append(message(unix.RTM_GET), message(unix.RTM_MISS)...)
	if isFreeBSDNetworkChange(lookups) {
		t.Fatal("route lookups must not retrigger network checks")
	}
	for _, kind := range []byte{unix.RTM_ADD, unix.RTM_DELETE, unix.RTM_CHANGE,
		unix.RTM_NEWADDR, unix.RTM_DELADDR, unix.RTM_IFINFO, unix.RTM_IFANNOUNCE} {
		if !isFreeBSDNetworkChange(append(lookups, message(kind)...)) {
			t.Errorf("ignored route message type %d", kind)
		}
	}
}
