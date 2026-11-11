//go:build freebsd && cgo

package main

/*
#cgo pkg-config: gtk4 webkitgtk-6.0

#include <gtk/gtk.h>
#include <webkit/webkit.h>
#include <stdlib.h>

static GtkApplication *desktop_app;
static const char *desktop_url;

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

static void activate(GtkApplication *app, gpointer unused) {
    GtkWindow *window = gtk_application_get_active_window(app);
    if (!window) {
        window = GTK_WINDOW(gtk_application_window_new(app));
        gtk_window_set_title(window, "MySafeAI");
        gtk_window_set_default_size(window, 420, 550);
        gtk_widget_set_size_request(GTK_WIDGET(window), 340, 440);
        GtkWidget *view = webkit_web_view_new();
        g_signal_connect(view, "decide-policy", G_CALLBACK(decide_navigation), NULL);
        gtk_window_set_child(window, view);
        webkit_web_view_load_uri(WEBKIT_WEB_VIEW(view), desktop_url);
    }
    gtk_window_present(window);
}

static gboolean quit_desktop(gpointer unused) {
    if (desktop_app) {
        g_application_quit(G_APPLICATION(desktop_app));
    }
    return G_SOURCE_REMOVE;
}

static void request_quit(void) {
    g_main_context_invoke(NULL, quit_desktop, NULL);
}

static int run_desktop(const char *url) {
    desktop_url = url;
    desktop_app = gtk_application_new("app.mysafeai.desktop", G_APPLICATION_DEFAULT_FLAGS);
    g_signal_connect(desktop_app, "activate", G_CALLBACK(activate), NULL);
    int status = g_application_run(G_APPLICATION(desktop_app), 0, NULL);
    g_object_unref(desktop_app);
    desktop_app = NULL;
    desktop_url = NULL;
    return status;
}
*/
import "C"

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
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
	var ready atomic.Bool
	ui := &panel{storage: s, ctx: ctx, running: make(map[string]session), token: secret(),
		smoke: smoke, tray: func() bool { return false }}
	defer func() {
		cancel()
		ui.shutdown()
	}()
	ui.stop = func() {
		ready.Store(true)
		C.request_quit()
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
		select {
		case <-parent.Done():
			C.request_quit()
		case <-ctx.Done():
		}
	}()

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	url := C.CString("http://" + host + prefix)
	defer C.free(unsafe.Pointer(url))
	if status := C.run_desktop(url); status != 0 {
		return fmt.Errorf("GTK exited with status %d", status)
	}
	if smoke && !ready.Load() {
		return errors.New("the FreeBSD window did not load the embedded panel")
	}
	return nil
}
