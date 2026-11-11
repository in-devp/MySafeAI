//go:build (linux || freebsd) && cgo

package main

/*
#cgo pkg-config: gio-2.0
#include <gio/gio.h>
#include <stdlib.h>

static gchar *mysafeai_proxy_lookup(const gchar *uri, GCancellable *cancel, int *unavailable) {
    GProxyResolver *resolver = g_proxy_resolver_get_default();
    if (!resolver || g_str_equal(G_OBJECT_TYPE_NAME(resolver), "GDummyProxyResolver")) {
        *unavailable = 1;
        return NULL;
    }

    gchar **proxies = g_proxy_resolver_lookup(resolver, uri, cancel, NULL);
    gchar *first = proxies && proxies[0] ? g_strdup(proxies[0]) : NULL;
    g_strfreev(proxies);
    return first;
}
*/
import "C"

import (
	"context"
	"errors"
	"net/url"
	"time"
	"unsafe"
)

func resolveSystemProxy(ctx context.Context, target *url.URL) (*url.URL, error) {
	if target == nil || target.Hostname() == "" || target.User != nil || target.Fragment != "" ||
		(target.Scheme != "http" && target.Scheme != "https") {
		return nil, errors.New("invalid URL for system proxy lookup")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	uri := C.CString(target.String())
	defer C.free(unsafe.Pointer(uri))
	cancellable := C.g_cancellable_new()
	finished := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		C.g_cancellable_cancel(cancellable)
		close(finished)
	})
	defer func() {
		if !stop() {
			<-finished
		}
		C.g_object_unref(C.gpointer(cancellable))
	}()

	var unavailable C.int
	first := C.mysafeai_proxy_lookup(uri, cancellable, &unavailable)
	defer C.g_free(C.gpointer(first))
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if unavailable != 0 {
		return nil, errors.New("system proxy resolver is unavailable")
	}
	if first == nil {
		return nil, errors.New("system proxy lookup returned no route")
	}
	return parseGIOProxy(C.GoString(first))
}

func parseGIOProxy(uri string) (*url.URL, error) {
	// A failed connection must not fall back to another proxy or to DIRECT.
	if uri == "direct://" {
		return nil, nil
	}
	proxy, err := url.Parse(uri)
	if err != nil || proxy.Hostname() == "" || proxy.Opaque != "" || proxy.Fragment != "" ||
		proxy.ForceQuery || proxy.RawQuery != "" || (proxy.Path != "" && proxy.Path != "/") {
		return nil, errors.New("system proxy returned an invalid route")
	}
	switch proxy.Scheme {
	case "http", "https", "socks5", "socks5h":
	case "socks":
		// GIO orders generic SOCKS as SOCKS5, SOCKS4a, then SOCKS4.
		proxy.Scheme = "socks5"
	default:
		return nil, errors.New("system proxy selected an unsupported protocol")
	}
	return proxy, nil
}
