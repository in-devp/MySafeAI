package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"
)

const usage = `MySafeAI for Windows and Linux
  mysafeai                 Open the MySafeAI desktop app
  mysafeai check           Print the VPN route and IP checks as JSON
  mysafeai run -- command  Run a program under VPN monitoring
`

type storage struct{ dir string }

func localStorage() (storage, error) {
	root, err := os.UserConfigDir()
	if err != nil {
		return storage{}, err
	}
	dir := filepath.Join(root, "MySafeAI")
	return storage{dir}, os.MkdirAll(dir, 0o700)
}

func (s storage) load() (config, error) {
	var c config
	data, err := os.ReadFile(filepath.Join(s.dir, "portable.json"))
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	return c, json.Unmarshal(data, &c)
}

func (s storage) save(c config) error {
	if err := c.validate(); err != nil {
		return err
	}
	file, err := os.CreateTemp(s.dir, "policy-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	writeErr := json.NewEncoder(file).Encode(c)
	closeErr := file.Close()
	if err := errors.Join(writeErr, closeErr); err != nil {
		return err
	}
	return os.Rename(file.Name(), filepath.Join(s.dir, "portable.json"))
}

func (s storage) event(message string) {
	f, err := os.OpenFile(filepath.Join(s.dir, "portable.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err == nil {
		defer f.Close()
		fmt.Fprintln(f, time.Now().Format(time.RFC3339), strings.Join(strings.Fields(message), " "))
	}
}

func (s storage) recent() []string {
	f, err := os.Open(filepath.Join(s.dir, "portable.log"))
	if err != nil {
		return []string{}
	}
	defer f.Close()
	if info, err := f.Stat(); err == nil && info.Size() > 16384 {
		_, _ = f.Seek(info.Size()-16384, io.SeekStart)
	}
	data, _ := io.ReadAll(io.LimitReader(f, 16384))
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) > 12 {
		lines = lines[len(lines)-12:]
	}
	return lines
}

func main() {
	args := os.Args[1:]
	if len(args) > 0 && args[0] == "_gate" {
		code, err := launchGate(args[1:])
		finish(code, err)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	code, err := run(ctx, args)
	cancel()
	finish(code, err)
}

func finish(code int, err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "MySafeAI:", err)
		if code == 0 {
			code = 1
		}
	}
	if code < 0 {
		code = 1
	}
	os.Exit(code)
}

func run(ctx context.Context, args []string) (int, error) {
	if len(args) == 0 {
		args = []string{"ui"}
	}
	if args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		fmt.Print(usage)
		return 0, nil
	}
	if args[0] == "_smoke-ui" && len(args) == 1 {
		dir, err := os.MkdirTemp("", "mysafeai-ui-")
		if err != nil {
			return 1, err
		}
		defer os.RemoveAll(dir)
		return 0, runDesktop(ctx, storage{dir}, true)
	}
	s, err := localStorage()
	if err != nil {
		return 1, err
	}
	switch args[0] {
	case "ui":
		if len(args) != 1 {
			return 64, errors.New("usage: mysafeai ui")
		}
		return 0, runDesktop(ctx, s, false)
	case "check":
		if len(args) != 1 {
			return 64, errors.New("usage: mysafeai check")
		}
		c, err := s.load()
		if err != nil {
			return 1, err
		}
		result := verify(ctx, c)
		if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
			return 1, err
		}
		if !result.Trusted {
			return 69, nil
		}
		return 0, nil
	case "run":
		if len(args) < 3 || args[1] != "--" {
			return 64, errors.New("usage: mysafeai run -- command [arguments]")
		}
		c, err := s.load()
		if err != nil {
			return 1, err
		}
		return startManaged(ctx, args[2:], c, liveCheck, streams{os.Stdin, os.Stdout, os.Stderr}, func(_ runState, event string) { s.event(event) })
	default:
		return 64, errors.New("unknown command; see mysafeai --help")
	}
}
