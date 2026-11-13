//go:build freebsd && cgo

package main

/*
#cgo pkg-config: gtk4 webkitgtk-6.0

#include <gtk/gtk.h>
#include <webkit/webkit.h>
#include <stdlib.h>

static GtkApplication *desktop_app;
static GtkWindow *desktop_window;
static const char *desktop_url;
static const char *icon_dir;
static gint tray_available;
static gboolean start_hidden;
static gboolean primary_desktop;
static GtkNativeDialog *picker_dialog;
static GAsyncQueue *picker_queue;
static char picker_cancelled;

static void free_picker_result(gpointer item) {
    if (item != &picker_cancelled) {
        g_free(item);
    }
}

static void finish_picker(char *path) {
    if (!picker_queue) {
        g_free(path);
        return;
    }
    g_signal_handlers_disconnect_by_data(picker_dialog, picker_queue);
    gtk_native_dialog_destroy(picker_dialog);
    g_object_unref(picker_dialog);
    picker_dialog = NULL;
    g_async_queue_push(picker_queue, path ? path : &picker_cancelled);
    g_async_queue_unref(picker_queue);
    picker_queue = NULL;
}

static void picker_response(GtkNativeDialog *dialog, int response, gpointer unused) {
    char *path = NULL;
    if (response == GTK_RESPONSE_ACCEPT) {
        GFile *file = gtk_file_chooser_get_file(GTK_FILE_CHOOSER(dialog));
        if (file) {
            path = g_file_get_path(file);
            g_object_unref(file);
        }
    }
    finish_picker(path);
}

typedef struct { GAsyncQueue *queue; int english; } PickerRequest;

static gboolean open_picker(gpointer data) {
    PickerRequest *request = data;
    GAsyncQueue *queue = request->queue;
    int english = request->english;
    g_free(request);
    if (!desktop_window || picker_queue) {
        g_async_queue_push(queue, &picker_cancelled);
        g_async_queue_unref(queue);
        return G_SOURCE_REMOVE;
    }
    picker_queue = queue;
    picker_dialog = GTK_NATIVE_DIALOG(gtk_file_chooser_native_new(english ? "Choose an application" : "Выбрать программу", desktop_window,
        GTK_FILE_CHOOSER_ACTION_OPEN, english ? "Choose" : "Выбрать", english ? "Cancel" : "Отмена"));
    g_signal_connect(picker_dialog, "response", G_CALLBACK(picker_response), queue);
    gtk_native_dialog_set_modal(picker_dialog, TRUE);
    gtk_native_dialog_show(picker_dialog);
    return G_SOURCE_REMOVE;
}

static char *pick_program(int english) {
    GAsyncQueue *queue = g_async_queue_new_full(free_picker_result);
    PickerRequest *request = g_new0(PickerRequest, 1);
    request->queue = g_async_queue_ref(queue);
    request->english = english;
    g_idle_add(open_picker, request);
    gpointer result = g_async_queue_timeout_pop(queue, 90 * G_TIME_SPAN_SECOND);
    g_async_queue_unref(queue);
    return result == &picker_cancelled ? NULL : result;
}

static gboolean decide_navigation(WebKitWebView *view, WebKitPolicyDecision *decision,
                                  WebKitPolicyDecisionType type, gpointer unused) {
    if (type == WEBKIT_POLICY_DECISION_TYPE_NEW_WINDOW_ACTION) {
        webkit_policy_decision_ignore(decision);
        return TRUE;
    }
    if (type != WEBKIT_POLICY_DECISION_TYPE_NAVIGATION_ACTION) {
        return FALSE;
    }
    WebKitNavigationAction *action = webkit_navigation_policy_decision_get_navigation_action(
        WEBKIT_NAVIGATION_POLICY_DECISION(decision));
    const char *uri = webkit_uri_request_get_uri(webkit_navigation_action_get_request(action));
    if (!uri || !g_str_has_prefix(uri, desktop_url)) {
        webkit_policy_decision_ignore(decision);
        return TRUE;
    }
    return FALSE;
}

static gboolean hide_desktop(gpointer unused) {
    if (desktop_window && g_atomic_int_get(&tray_available)) {
        gtk_widget_set_visible(GTK_WIDGET(desktop_window), FALSE);
    }
    return G_SOURCE_REMOVE;
}

static gboolean close_window(GtkWindow *window, gpointer unused) {
    if (!g_atomic_int_get(&tray_available)) {
        return FALSE;
    }
    hide_desktop(NULL);
    return TRUE;
}

static void activate(GtkApplication *app, gpointer unused) {
    primary_desktop = TRUE;
    if (desktop_window) {
        gtk_window_present(desktop_window);
        return;
    }
    desktop_window = GTK_WINDOW(gtk_application_window_new(app));
    g_object_add_weak_pointer(G_OBJECT(desktop_window), (gpointer *)&desktop_window);
    gtk_window_set_title(desktop_window, "MySafeAI");
    gtk_window_set_default_size(desktop_window, 420, 550);
    gtk_widget_set_size_request(GTK_WIDGET(desktop_window), 340, 440);
    GtkIconTheme *theme = gtk_icon_theme_get_for_display(gtk_widget_get_display(GTK_WIDGET(desktop_window)));
    gtk_icon_theme_add_search_path(theme, icon_dir);
    gtk_window_set_icon_name(desktop_window, "app.mysafeai.desktop");
    GtkWidget *view = webkit_web_view_new();
    g_signal_connect(view, "decide-policy", G_CALLBACK(decide_navigation), NULL);
    g_signal_connect(desktop_window, "close-request", G_CALLBACK(close_window), NULL);
    gtk_window_set_child(desktop_window, view);
    webkit_web_view_load_uri(WEBKIT_WEB_VIEW(view), desktop_url);
    if (!start_hidden || !g_atomic_int_get(&tray_available)) {
        gtk_window_present(desktop_window);
    }
    start_hidden = FALSE;
}

static gboolean show_desktop(gpointer unused) {
    if (desktop_app) {
        g_application_activate(G_APPLICATION(desktop_app));
    }
    return G_SOURCE_REMOVE;
}

static gboolean restore_without_tray(gpointer unused) {
    if (desktop_window && !gtk_widget_get_visible(GTK_WIDGET(desktop_window))
        && !g_atomic_int_get(&tray_available)) {
        gtk_window_present(desktop_window);
    }
    return G_SOURCE_REMOVE;
}

static gboolean quit_desktop(gpointer unused) {
    if (desktop_app) {
        finish_picker(NULL);
        g_application_quit(G_APPLICATION(desktop_app));
    }
    return G_SOURCE_REMOVE;
}

static void request_quit(void) {
    g_idle_add(quit_desktop, NULL);
}

static void request_show(void) { g_idle_add(show_desktop, NULL); }
static void request_hide(void) { g_idle_add(hide_desktop, NULL); }
static gboolean was_primary_desktop(void) { return primary_desktop; }

static void set_tray_available(gint available) {
    if (g_atomic_int_exchange(&tray_available, available) && !available) {
        g_idle_add(restore_without_tray, NULL);
    }
}

static int run_desktop(const char *url, const char *icons, gboolean hidden) {
    desktop_url = url;
    icon_dir = icons;
    start_hidden = hidden;
    desktop_app = gtk_application_new("app.mysafeai.desktop", G_APPLICATION_DEFAULT_FLAGS);
    g_signal_connect(desktop_app, "activate", G_CALLBACK(activate), NULL);
    int status = g_application_run(G_APPLICATION(desktop_app), 0, NULL);
    finish_picker(NULL);
    g_object_unref(desktop_app);
    desktop_app = NULL;
    desktop_url = NULL;
    icon_dir = NULL;
    return status;
}
*/
import "C"

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"
)

func runDesktop(parent context.Context, s storage, smoke bool) error {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer listener.Close()

	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	trayOnly, err := s.loadTrayOnly()
	if err != nil {
		log.Printf("window preferences: %v", err)
	}
	iconDir, err := os.MkdirTemp("", "mysafeai-icon-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(iconDir)
	icon, err := web.ReadFile("web/tray.png")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(iconDir, "app.mysafeai.desktop.png"), icon, 0o600); err != nil {
		return err
	}
	tray, _ := openFreeBSDTray(icon, func() { C.request_show() })
	var hasTray atomic.Bool
	updateTray := func(available bool) {
		hasTray.Store(available)
		if available {
			C.set_tray_available(1)
		} else {
			C.set_tray_available(0)
		}
	}
	if tray != nil {
		defer tray.conn.Close()
		updateTray(tray.refresh())
	}
	var ready atomic.Bool
	ui := &panel{storage: s, ctx: ctx, running: make(map[string]session), token: secret(),
		smoke: smoke, tray: hasTray.Load, trayOnly: trayOnly, hide: func() { C.request_hide() }}
	ui.pick = func() (string, error) {
		var english C.int
		if userLanguage() == "en" {
			english = 1
		}
		path := C.pick_program(english)
		if path == nil {
			return "", nil
		}
		defer C.g_free(C.gpointer(unsafe.Pointer(path)))
		return C.GoString(path), nil
	}
	defer func() {
		cancel()
		if C.was_primary_desktop() == 0 {
			ui.monitor = nil
		}
		ui.shutdown()
	}()
	ui.stop = func() {
		ready.Store(true)
		C.request_quit()
	}
	if !smoke {
		ui.monitor = startWatchClient(ctx, s, func() { C.request_show() })
	}

	host := listener.Addr().String()
	prefix := "/" + secret() + "/"
	handler := http.StripPrefix(strings.TrimSuffix(prefix, "/"), ui.handler())
	server := &http.Server{
		ReadHeaderTimeout: 3 * time.Second,
		BaseContext:       func(net.Listener) context.Context { return ctx },
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Host != host || !strings.HasPrefix(r.URL.Path, prefix) {
				http.NotFound(w, r)
				return
			}
			handler.ServeHTTP(w, r)
		}),
	}
	defer server.Close()
	go func() { _ = server.Serve(listener) }()

	if smoke {
		timeout := time.AfterFunc(25*time.Second, func() {
			finish(70, errors.New("the FreeBSD window did not finish its startup and shutdown check"))
		})
		defer timeout.Stop()
	}
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-parent.Done():
				C.request_quit()
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				if tray != nil {
					updateTray(tray.refresh())
				}
			}
		}
	}()

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	url := C.CString("http://" + host + prefix)
	defer C.free(unsafe.Pointer(url))
	icons := C.CString(iconDir)
	defer C.free(unsafe.Pointer(icons))
	var hidden C.gboolean
	if trayOnly || startsInBackground(parent) {
		hidden = 1
	}
	if status := C.run_desktop(url, icons, hidden); status != 0 {
		return fmt.Errorf("GTK exited with status %d", status)
	}
	if smoke && !ready.Load() {
		return errors.New("the FreeBSD window did not load the embedded panel")
	}
	return nil
}
