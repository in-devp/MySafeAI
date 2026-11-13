package main

import (
	"fmt"
	"os"
	"time"

	"github.com/in-devp/MySafeAI/portable/browserbridge"
)

const usage = `MySafeAI browser bridge
  mysafeai-browser-host --install [chrome|chromium|edge|brave|firefox|all]
  mysafeai-browser-host --uninstall [chrome|chromium|edge|brave|firefox|all]

Registers the browser bridge for the current user. No administrator rights are
needed. Keep the executable in its installed location after registration.
Chrome and Brave share a registration on macOS and Windows.
`

func main() {
	args := os.Args[1:]
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		fmt.Print(usage)
		return
	}
	executable, err := os.Executable()
	if err != nil {
		fail("Cannot locate the browser bridge.")
	}
	if len(args) >= 1 && (args[0] == "--install" || args[0] == "--uninstall") {
		if len(args) > 2 {
			fail("Invalid installation arguments; see --help.")
		}
		browser := "all"
		if len(args) == 2 {
			browser = args[1]
		}
		if args[0] == "--install" {
			err = browserbridge.Install(executable, browser)
		} else {
			err = browserbridge.Uninstall(executable, browser)
		}
		if err != nil {
			fail(err.Error())
		}
		fmt.Println("MySafeAI browser bridge registration updated.")
		return
	}
	if !browserbridge.ValidInvocation(args, executable) {
		fail("This helper must be started by the MySafeAI extension; see --help.")
	}
	filename, err := browserbridge.SnapshotPath()
	if err != nil {
		fail("Cannot locate local protection status.")
	}
	err = browserbridge.Serve(os.Stdin, os.Stdout, func() browserbridge.Response {
		return browserbridge.ReadStatus(filename, time.Now())
	})
	if err != nil {
		fail("Browser bridge connection closed after an invalid or incomplete message.")
	}
}

func fail(message string) {
	fmt.Fprintln(os.Stderr, "MySafeAI:", message)
	os.Exit(1)
}
