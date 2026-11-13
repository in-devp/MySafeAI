//go:build linux || windows

package main

import (
	"context"
	"errors"
	"log"
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
	trayOnly, err := s.loadTrayOnly()
	if err != nil {
		log.Printf("window preferences: %v", err)
		trayOnly = false
	}
	trayOnStartup := trayAvailable()
	if smoke && !trayOnStartup {
		trayOnly = true
		if err := s.saveJSON("window.json", windowPreferences{TrayOnly: true}); err != nil {
			return err
		}
	}
	ui := &panel{storage: s, ctx: ctx, running: make(map[string]session), token: secret(),
		smoke: smoke, tray: trayAvailable, trayOnly: trayOnly}
	var ready atomic.Bool
	var hiddenToTray atomic.Bool
	hiddenToTray.Store((trayOnly || startsInBackground(parent)) && trayOnStartup)
	var app *application.App
	var window *application.WebviewWindow

	options := application.Options{
		Name:        "MySafeAI",
		Description: nativeText("Монитор маршрутов и VPN-защита", "Network monitoring and application protection"),
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
		hiddenToTray.Store(false)
		if window.IsMinimised() {
			window.UnMinimise()
		}
		window.Show()
		window.Focus()
	}
	hide := func() {
		if trayAvailable() {
			hiddenToTray.Store(true)
			window.Hide()
		}
	}
	ui.hide = func() { application.InvokeAsync(hide) }
	if !smoke {
		options.SingleInstance = &application.SingleInstanceOptions{
			UniqueID:               "app.mysafeai.desktop",
			OnSecondInstanceLaunch: func(application.SecondInstanceData) { application.InvokeAsync(show) },
		}
	}
	app = application.New(options)
	window = app.Window.NewWithOptions(application.WebviewWindowOptions{
		Name:             "MySafeAI",
		Title:            "MySafeAI",
		Width:            400,
		Height:           535,
		MinWidth:         340,
		MinHeight:        440,
		Hidden:           hiddenToTray.Load(),
		BackgroundColour: application.NewRGB(20, 21, 27),
	})
	ui.stop = func() {
		application.InvokeAsync(func() {
			if smoke {
				if trayOnStartup {
					persisted, err := s.loadTrayOnly()
					if err != nil || !persisted || window.IsVisible() {
						finish(70, errors.New("tray-only mode did not persist and hide the window"))
					}
					show()
					if !window.IsVisible() {
						finish(70, errors.New("the desktop window did not reopen"))
					}
				} else if !window.IsVisible() {
					finish(70, errors.New("the window must stay available without a tray"))
				} else {
					window.Hide()
					if window.IsVisible() {
						finish(70, errors.New("the desktop window did not hide"))
					}
					show()
					if !window.IsVisible() {
						finish(70, errors.New("the desktop window did not reopen"))
					}
				}
				ready.Store(true)
			}
			app.Quit()
		})
	}

	ui.pick = func() (string, error) {
		dialog := app.Dialog.OpenFileWithOptions(&application.OpenFileDialogOptions{
			Title: nativeText("Выбрать программу", "Choose an application"), CanChooseFiles: true, AllowsOtherFileTypes: true, Window: window,
		})
		return dialog.PromptForSingleSelection()
	}
	tray := app.SystemTray.New()
	tray.SetIcon(icon)
	tray.SetTooltip("MySafeAI")
	tray.OnClick(func() { application.InvokeAsync(show) })
	menu := app.Menu.New()
	openItem := menu.Add(nativeText("Открыть MySafeAI", "Open MySafeAI")).OnClick(func(*application.Context) { application.InvokeAsync(show) })
	hideItem := menu.Add(nativeText("Скрыть окно", "Hide window")).OnClick(func(*application.Context) { application.InvokeAsync(hide) })
	menu.AddSeparator()
	quitItem := menu.Add(nativeText("Выйти", "Quit")).OnClick(func(*application.Context) { app.Quit() })
	tray.SetMenu(menu)
	window.RegisterHook(events.Common.WindowClosing, func(event *application.WindowEvent) {
		if trayAvailable() {
			event.Cancel()
			hiddenToTray.Store(true)
			window.Hide()
		}
	})

	if !smoke {
		ui.monitor = startWatchClient(ctx, s, func() { application.InvokeAsync(show) })
	}

	if smoke {
		timeout := time.AfterFunc(25*time.Second, func() {
			finish(70, errors.New("the native window did not finish its startup and shutdown check"))
		})
		defer timeout.Stop()
	}
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		lastLanguage := userLanguage()
		for {
			select {
			case <-parent.Done():
				app.Quit()
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				if language := userLanguage(); language != lastLanguage {
					lastLanguage = language
					application.InvokeAsync(func() {
						openItem.SetLabel(nativeText("Открыть MySafeAI", "Open MySafeAI"))
						hideItem.SetLabel(nativeText("Скрыть окно", "Hide window"))
						quitItem.SetLabel(nativeText("Выйти", "Quit"))
					})
				}
				if hiddenToTray.Load() && !trayAvailable() {
					application.InvokeAsync(show)
				}
			}
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
