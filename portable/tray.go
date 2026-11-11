//go:build linux || windows

package main

import (
	"context"
	"encoding/binary"
	"log"
	"runtime"

	"fyne.io/systray"
)

func startTray(ctx context.Context, url string, exit context.CancelFunc) {
	icon, err := web.ReadFile("web/tray.png")
	if err != nil {
		return
	}
	if runtime.GOOS == "windows" {
		// ICO supports one PNG-backed entry on current Windows versions.
		header := []byte{0, 0, 1, 0, 1, 0, 48, 48, 0, 0, 1, 0, 32, 0}
		header = binary.LittleEndian.AppendUint32(header, uint32(len(icon)))
		header = binary.LittleEndian.AppendUint32(header, 22)
		icon = append(header, icon...)
	}
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		systray.Run(func() {
			systray.SetIcon(icon)
			systray.SetTitle("MySafeAI")
			systray.SetTooltip("MySafeAI")
			show := systray.AddMenuItem("Открыть MySafeAI", "")
			quit := systray.AddMenuItem("Выйти", "")
			open := func() {
				if err := openBrowser(url); err != nil {
					log.Println(err)
				}
			}
			systray.SetOnTapped(open)
			go func() {
				defer systray.Quit()
				for {
					select {
					case <-show.ClickedCh:
						open()
					case <-quit.ClickedCh:
						exit()
						return
					case <-ctx.Done():
						return
					}
				}
			}()
		}, nil)
	}()
}
