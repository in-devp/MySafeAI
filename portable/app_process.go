package main

import (
	"errors"
	"path"
	"runtime"
	"sort"
	"strings"
)

type appProcessKey struct {
	PID     int    `json:"pid"`
	Started uint64 `json:"started"`
}

type appProcess struct {
	Key        appProcessKey
	Parent     int
	Order      uint64
	Executable string
	Arguments  []string
	Stopped    bool
}

type appProcessAction uint8

const (
	appPause appProcessAction = iota
	appResume
	appTerminate
	appKill
)

var errAppProcessAlreadyStopped = errors.New("application is already stopped")

type appTarget struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Executable string `json:"executable,omitempty"`
}

var builtInTargets = []appTarget{
	{ID: "codex-cli", Name: "Codex CLI"},
	{ID: "claude-code", Name: "Claude Code"},
	{ID: "codex-desktop", Name: "Codex"},
	{ID: "chatgpt", Name: "ChatGPT"},
	{ID: "cursor", Name: "Cursor"},
	{ID: "claude-desktop", Name: "Claude Desktop"},
}

func executableBase(executable string) string {
	name := path.Base(strings.ReplaceAll(executable, "\\", "/"))
	return strings.TrimSuffix(strings.ToLower(name), ".exe")
}

func presetForProcess(process appProcess) string {
	name := executableBase(process.Executable)
	location := strings.ToLower(strings.ReplaceAll(process.Executable, "\\", "/"))
	switch name {
	case "cursor", "cursor-nightly":
		return "cursor"
	case "chatgpt":
		return "chatgpt"
	case "codex-desktop":
		return "codex-desktop"
	case "claude-desktop":
		return "claude-desktop"
	case "claude":
		if strings.Contains(location, "/anthropic.claude") ||
			strings.Contains(location, "/claude/app-") || strings.Contains(location, "/claude-desktop/") {
			return "claude-desktop"
		}
		return "claude-code"
	case "codex", "codex-x86_64-unknown-linux-musl", "codex-aarch64-unknown-linux-musl",
		"codex-x86_64-pc-windows-msvc", "codex-aarch64-pc-windows-msvc":
		if strings.Contains(location, "/openai.codex_") || strings.Contains(location, "/codex-desktop/") {
			return "codex-desktop"
		}
		return "codex-cli"
	case "node", "nodejs", "bun":
		if len(process.Arguments) < 2 {
			return ""
		}
		script := strings.ToLower(strings.ReplaceAll(process.Arguments[1], "\\", "/"))
		if strings.HasSuffix(script, "/@openai/codex/bin/codex.js") {
			return "codex-cli"
		}
		if strings.HasSuffix(script, "/@anthropic-ai/claude-code/cli.js") {
			return "claude-code"
		}
	default:
		if strings.Contains(location, "/.local/share/claude/versions/") {
			return "claude-code"
		}
	}
	return ""
}

func matchesExecutable(expected, actual string) bool {
	if runtime.GOOS == "windows" {
		return strings.EqualFold(expected, actual)
	}
	return expected == actual
}

func managedGate(process appProcess) bool {
	name := executableBase(process.Executable)
	return (name == "mysafeai" || name == "mysafeai-desktop") &&
		len(process.Arguments) > 1 && process.Arguments[1] == "_gate"
}

type watchedProcess struct {
	appProcess
	targets []string
	depth   int
}

func watchedProcesses(processes []appProcess, targets []appTarget, self int) []watchedProcess {
	byPID := make(map[int]appProcess, len(processes))
	for _, process := range processes {
		if process.Key.PID > 1 && process.Key.Started != 0 {
			byPID[process.Key.PID] = process
		}
	}
	presets := make(map[string]bool)
	var custom []appTarget
	for _, target := range targets {
		if target.Executable == "" {
			presets[target.ID] = true
		} else {
			custom = append(custom, target)
		}
	}
	parentOf := func(process appProcess) appProcess {
		parent := byPID[process.Parent]
		if parent.Order > process.Order {
			return appProcess{} // Reused PID cannot be the child's parent.
		}
		return parent
	}
	protected := map[int]bool{}
	for process := byPID[self]; process.Key.PID != 0 && !protected[process.Key.PID]; process = parentOf(process) {
		protected[process.Key.PID] = true
	}
	resolved := make(map[int]watchedProcess, len(byPID))
	excluded := make(map[int]bool)
	visiting := make(map[int]bool)
	var resolve func(appProcess) watchedProcess
	resolve = func(process appProcess) watchedProcess {
		pid := process.Key.PID
		if pid == 0 || visiting[pid] || protected[pid] {
			return watchedProcess{}
		}
		if result, ok := resolved[pid]; ok {
			return result
		}
		visiting[pid] = true
		defer delete(visiting, pid)
		parent := parentOf(process)
		inherited := resolve(parent)
		result := watchedProcess{appProcess: process, depth: inherited.depth + 1}
		excluded[pid] = managedGate(process) || excluded[parent.Key.PID]
		if !excluded[pid] {
			result.targets = append([]string(nil), inherited.targets...)
			add := func(id string) {
				for _, existing := range result.targets {
					if id == existing {
						return
					}
				}
				result.targets = append(result.targets, id)
			}
			if id := presetForProcess(process); presets[id] {
				add(id)
			}
			for _, target := range custom {
				if matchesExecutable(target.Executable, process.Executable) {
					add(target.ID)
				}
			}
		}
		resolved[pid] = result
		return result
	}
	var result []watchedProcess
	for _, process := range byPID {
		if item := resolve(process); len(item.targets) > 0 {
			result = append(result, item)
		}
	}
	sort.Slice(result, func(a, b int) bool {
		if result[a].depth != result[b].depth {
			return result[a].depth < result[b].depth
		}
		return result[a].Key.PID < result[b].Key.PID
	})
	return result
}
