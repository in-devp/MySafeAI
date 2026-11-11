//go:build linux || windows

package main

import (
	"context"
	"errors"
	"sync/atomic"
	"time"

	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/events"
)

func runDesktop(parent context.Context, s storage, smoke bool) error {
	icon, err := web.ReadFile("web/tray.png")
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	ui := &panel{storage: s, ctx: ctx, running: make(map[string]session), token: secret(), smoke: smoke}
	var ready atomic.Bool
	var app *application.App
	var window *application.WebviewWindow

	options := application.Options{
		Name:        "MySafeAI",
		Description: "Монитор маршрутов и VPN-защита",
		Icon:        icon,
		Assets:      application.AssetOptions{DisableLogging: true, Handler: ui.handler()},
		OnShutdown: func() {
			cancel()
			ui.shutdown()
		},
		DisableDefaultSignalHandler: true,
		Linux:                       application.LinuxOptions{ApplicationID: "app.mysafeai.desktop"},
		Windows:                     application.WindowsOptions{DisableQuitOnLastWindowClosed: true},
	}
	show := func() {
		window.UnMinimise()
		window.Show()
		window.Focus()
	}
	if !smoke {
		options.SingleInstance = &application.SingleInstanceOptions{
			UniqueID:               "app.mysafeai.desktop",
			OnSecondInstanceLaunch: func(application.SecondInstanceData) { show() },
		}
	}
	app = application.New(options)
	ui.stop = func() {
		ready.Store(true)
		go app.Quit()
	}
	window = app.Window.NewWithOptions(application.WebviewWindowOptions{
		Name:             "MySafeAI",
		Title:            "MySafeAI",
		Width:            400,
		Height:           535,
		MinWidth:         340,
		MinHeight:        440,
		BackgroundColour: application.NewRGB(20, 21, 27),
	})

	if !smoke {
		tray := app.SystemTray.New()
		tray.SetIcon(icon)
		tray.SetTooltip("MySafeAI")
		tray.OnClick(show)
		menu := app.Menu.New()
		menu.Add("Открыть MySafeAI").OnClick(func(*application.Context) { show() })
		menu.AddSeparator()
		menu.Add("Выйти").OnClick(func(*application.Context) { app.Quit() })
		tray.SetMenu(menu)
		window.RegisterHook(events.Common.WindowClosing, func(event *application.WindowEvent) {
			if trayAvailable() {
				event.Cancel()
				window.Hide()
			}
		})
	}

	if smoke {
		timeout := time.AfterFunc(25*time.Second, func() {
			if !ready.Load() {
				finish(70, errors.New("the native window did not load the embedded panel"))
			}
		})
		defer timeout.Stop()
	}
	go func() {
		select {
		case <-parent.Done():
			app.Quit()
		case <-ctx.Done():
		}
	}()
	if err := app.Run(); err != nil {
		return err
	}
	if smoke && !ready.Load() {
		return errors.New("the native window did not load the embedded panel")
	}
	return nil
}
