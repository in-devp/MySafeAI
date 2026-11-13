package browserbridge

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSnapshotAdmissionRequiresFreshConsistentLease(t *testing.T) {
	now := time.UnixMilli(1800000000000)
	base := Snapshot{Protocol: Protocol, Allowed: true, State: "trusted", UpdatedAt: now.UnixMilli() - 1000, ValidUntil: now.UnixMilli() + 1000}
	for _, state := range []string{"trusted", "disabled", "paused"} {
		s := base
		s.State = state
		if r := s.Response(now); !r.Allowed || r.State != state {
			t.Fatalf("valid %s denied: %+v", state, r)
		}
	}
	for _, test := range []struct {
		name   string
		change func(*Snapshot)
	}{
		{"wrong protocol", func(s *Snapshot) { s.Protocol = 2 }},
		{"future heartbeat", func(s *Snapshot) { s.UpdatedAt = now.UnixMilli() + 1 }},
		{"stale heartbeat", func(s *Snapshot) { s.UpdatedAt = now.UnixMilli() - 3000 }},
		{"expired lease", func(s *Snapshot) { s.ValidUntil = now.UnixMilli() }},
		{"excessive ttl", func(s *Snapshot) { s.ValidUntil = s.UpdatedAt + 3001 }},
		{"unknown state", func(s *Snapshot) { s.State = "running" }},
		{"allowed block", func(s *Snapshot) { s.State = "blocked" }},
		{"denied trusted", func(s *Snapshot) { s.Allowed = false }},
		{"missing heartbeat", func(s *Snapshot) { s.UpdatedAt = 0 }},
		{"negative expiry", func(s *Snapshot) { s.ValidUntil = -1 }},
		{"overflow timestamp", func(s *Snapshot) { s.UpdatedAt = 1<<63 - 1 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := base
			test.change(&s)
			if r := s.Response(now); r.Allowed || r.State != "unavailable" {
				t.Fatalf("invalid snapshot admitted: %+v", r)
			}
		})
	}
	base.State, base.Allowed = "blocked", false
	if r := base.Response(now); r.Allowed || r.State != "blocked" {
		t.Fatalf("blocked: %+v", r)
	}
}

func TestStatusFileFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), SnapshotFilename)
	now := time.Now()
	if ReadStatus(path, now).Allowed {
		t.Fatal("missing file allowed")
	}
	for _, data := range []string{
		"null", "{}", "[]", "false", "{", `{"protocol":1,"allowed":true,"state":"trusted"}`,
		`{"protocol":1} {"allowed":true}`, string(make([]byte, 4097)),
	} {
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		if ReadStatus(path, now).Allowed {
			t.Fatal("corrupt file allowed")
		}
	}
	snapshot := Snapshot{Protocol: 1, Allowed: true, State: "trusted", UpdatedAt: now.UnixMilli(), ValidUntil: now.Add(2 * time.Second).UnixMilli()}
	data, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if !ReadStatus(path, now).Allowed {
		t.Fatal("valid file denied")
	}
	if ReadStatus(path, now.Add(2*time.Second)).Allowed {
		t.Fatal("expired file allowed")
	}
	if err := os.WriteFile(path, append(data[:len(data)-1], []byte(`,"ip":"203.0.113.1"}`)...), 0o600); err != nil {
		t.Fatal(err)
	}
	if ReadStatus(path, now).Allowed {
		t.Fatal("unexpected schema allowed")
	}
}
