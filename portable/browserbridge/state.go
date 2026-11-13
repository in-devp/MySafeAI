// Package browserbridge is the read-only boundary between MySafeAI and its
// browser extension. It never handles page URLs, IP addresses or credentials.
package browserbridge

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"
)

const (
	Protocol         = 1
	SnapshotFilename = "browser-state.json"
	MaxSnapshotAge   = 3 * time.Second
)

// Snapshot is written atomically by the running application. A heartbeat must
// not renew the underlying network proof: the producer checks that separately.
type Snapshot struct {
	Protocol   int    `json:"protocol"`
	Allowed    bool   `json:"allowed"`
	State      string `json:"state"`
	UpdatedAt  int64  `json:"updatedAt"`
	ValidUntil int64  `json:"validUntil"`
}

type Response struct {
	Protocol int    `json:"protocol"`
	Allowed  bool   `json:"allowed"`
	State    string `json:"state"`
	Reason   string `json:"reason"`
}

func Unavailable() Response {
	return Response{Protocol: Protocol, State: "unavailable", Reason: "Откройте MySafeAI: свежего подтверждения защиты нет."}
}

// Response rejects future timestamps, expired leases and inconsistent states.
// Explicit manual suspension only permits browsing while the app is alive.
func (s Snapshot) Response(now time.Time) Response {
	n := now.UnixMilli()
	if s.Protocol != Protocol || s.UpdatedAt <= 0 || s.UpdatedAt > n ||
		n-s.UpdatedAt >= MaxSnapshotAge.Milliseconds() || s.ValidUntil <= n ||
		s.ValidUntil <= s.UpdatedAt || s.ValidUntil-s.UpdatedAt > MaxSnapshotAge.Milliseconds() {
		return Unavailable()
	}
	r := Response{Protocol: Protocol, Allowed: s.Allowed, State: s.State}
	switch s.State {
	case "trusted":
		if !s.Allowed {
			return Unavailable()
		}
		r.Reason = "Подключение подтверждено MySafeAI."
	case "disabled":
		if !s.Allowed {
			return Unavailable()
		}
		r.Reason = "Защита отключена в MySafeAI."
	case "paused":
		if !s.Allowed {
			return Unavailable()
		}
		r.Reason = "Защита временно приостановлена в MySafeAI."
	case "blocked":
		if s.Allowed {
			return Unavailable()
		}
		r.Reason = "MySafeAI ещё не подтвердил доверенное подключение."
	case "unavailable":
		return Unavailable()
	default:
		return Unavailable()
	}
	return r
}

func SnapshotPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "MySafeAI", SnapshotFilename), nil
}

func ReadStatus(filename string, now time.Time) Response {
	file, err := os.Open(filename)
	if err != nil {
		return Unavailable()
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 4096 {
		return Unavailable()
	}
	data, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil || len(data) > 4096 {
		return Unavailable()
	}
	var snapshot Snapshot
	if strictJSON(data, &snapshot) != nil {
		return Unavailable()
	}
	return snapshot.Response(now)
}

func strictJSON(data []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return errors.New("expected one JSON value")
	}
	return nil
}
