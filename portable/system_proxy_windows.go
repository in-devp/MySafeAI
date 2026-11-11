package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"path"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	winProxyNoProxy             = 1
	winProxyAsync               = 0x10000000
	winProxyAutoDetect          = 0x00000001
	winProxyConfigURL           = 0x00000002
	winProxyDetectDHCPAndDNS    = 0x00000003
	winProxyNoCacheClient       = 0x00080000
	winProxyNoCacheService      = 0x00100000
	winProxyRequestError        = 0x00200000
	winProxyLookupComplete      = 0x01000000
	winProxyAutoDetectionFailed = syscall.Errno(12180)
	// WINHTTP_PROXY_RESULT_ENTRY uses the INTERNET_SCHEME values in winhttp.h.
	winProxySchemeHTTP  = 1
	winProxySchemeHTTPS = 2
)

var (
	winProxyDLL            = windows.NewLazySystemDLL("winhttp.dll")
	winProxyGetUserConfig  = winProxyDLL.NewProc("WinHttpGetIEProxyConfigForCurrentUser")
	winProxyOpen           = winProxyDLL.NewProc("WinHttpOpen")
	winProxySetTimeouts    = winProxyDLL.NewProc("WinHttpSetTimeouts")
	winProxySetCallback    = winProxyDLL.NewProc("WinHttpSetStatusCallback")
	winProxyCreateResolver = winProxyDLL.NewProc("WinHttpCreateProxyResolver")
	winProxyLookup         = winProxyDLL.NewProc("WinHttpGetProxyForUrlEx")
	winProxyGetResult      = winProxyDLL.NewProc("WinHttpGetProxyResult")
	winProxyFreeResult     = winProxyDLL.NewProc("WinHttpFreeProxyResult")
	winProxyCloseHandle    = winProxyDLL.NewProc("WinHttpCloseHandle")
	winProxyGlobalFree     = windows.NewLazySystemDLL("kernel32.dll").NewProc("GlobalFree")

	winProxyRequests  sync.Map
	winProxyRequestID atomic.Uintptr
	winProxyCallback  = windows.NewCallback(proxyLookupCallback)
)

type winUserProxyConfig struct {
	autoDetect    uint32
	autoConfigURL *uint16
	proxy         *uint16
	bypass        *uint16
}

type winAutoProxyOptions struct {
	flags         uint32
	detectFlags   uint32
	autoConfigURL *uint16
	reserved      uintptr
	reservedDWORD uint32
	autoLogon     uint32
}

type winProxyResult struct {
	count   uint32
	entries *winProxyEntry
}

type winProxyEntry struct {
	proxy  uint32
	bypass uint32
	scheme int32
	host   *uint16
	port   uint16
}

type winProxyAsyncResult struct {
	result uintptr
	err    uint32
}

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

	var config winUserProxyConfig
	ok, _, err := winProxyGetUserConfig.Call(uintptr(unsafe.Pointer(&config)))
	defer func() {
		for _, value := range []*uint16{config.autoConfigURL, config.proxy, config.bypass} {
			if value != nil {
				winProxyGlobalFree.Call(uintptr(unsafe.Pointer(value)))
			}
		}
	}()
	if ok == 0 {
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
			return nil, nil
		}
		return nil, fmt.Errorf("read current-user proxy settings: %w", err)
	}

	options := winAutoProxyOptions{flags: winProxyNoCacheClient | winProxyNoCacheService}
	if config.autoDetect != 0 {
		options.flags |= winProxyAutoDetect
		options.detectFlags = winProxyDetectDHCPAndDNS
	}
	if windows.UTF16PtrToString(config.autoConfigURL) != "" {
		options.flags |= winProxyConfigURL
		options.autoConfigURL = config.autoConfigURL
	}
	if options.flags&(winProxyAutoDetect|winProxyConfigURL) != 0 {
		proxy, err := resolveWinAutoProxy(ctx, target, &options)
		if err == nil {
			return proxy, nil
		}
		// WPAD with no advertised configuration can use the manual settings.
		// A configured PAC that fails remains inconclusive.
		if options.autoConfigURL != nil || !errors.Is(err, winProxyAutoDetectionFailed) {
			return nil, err
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return resolveWinManualProxy(target, windows.UTF16PtrToString(config.proxy), windows.UTF16PtrToString(config.bypass))
}

func resolveWinAutoProxy(ctx context.Context, target *url.URL, options *winAutoProxyOptions) (*url.URL, error) {
	wideTarget, err := windows.UTF16PtrFromString(target.String())
	if err != nil {
		return nil, errors.New("invalid URL for automatic proxy lookup")
	}
	defer runtime.KeepAlive(wideTarget)
	defer runtime.KeepAlive(options)

	session, _, err := winProxyOpen.Call(0, winProxyNoProxy, 0, 0, winProxyAsync)
	if session == 0 {
		return nil, fmt.Errorf("open automatic proxy session: %w", err)
	}
	defer winProxyCloseHandle.Call(session)
	if ok, _, err := winProxySetTimeouts.Call(session, 3000, 3000, 3000, 3000); ok == 0 {
		return nil, fmt.Errorf("set automatic proxy timeouts: %w", err)
	}
	previous, _, err := winProxySetCallback.Call(session, winProxyCallback, winProxyRequestError|winProxyLookupComplete, 0)
	if previous == ^uintptr(0) {
		return nil, fmt.Errorf("register automatic proxy callback: %w", err)
	}
	var resolver uintptr
	status, _, _ := winProxyCreateResolver.Call(session, uintptr(unsafe.Pointer(&resolver)))
	if status != 0 {
		return nil, fmt.Errorf("create automatic proxy resolver: %w", syscall.Errno(status))
	}
	defer winProxyCloseHandle.Call(resolver)

	requestID := winProxyRequestID.Add(1)
	reply := make(chan uint32, 1)
	winProxyRequests.Store(requestID, reply)
	defer winProxyRequests.Delete(requestID)
	status, _, _ = winProxyLookup.Call(resolver, uintptr(unsafe.Pointer(wideTarget)), uintptr(unsafe.Pointer(options)), requestID)
	if syscall.Errno(status) != windows.ERROR_IO_PENDING {
		return nil, fmt.Errorf("start automatic proxy lookup: %w", syscall.Errno(status))
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case result := <-reply:
		if result != 0 {
			return nil, fmt.Errorf("automatic proxy lookup: %w", syscall.Errno(result))
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	var result winProxyResult
	status, _, _ = winProxyGetResult.Call(resolver, uintptr(unsafe.Pointer(&result)))
	if status != 0 {
		return nil, fmt.Errorf("read automatic proxy result: %w", syscall.Errno(status))
	}
	defer func() { winProxyFreeResult.Call(uintptr(unsafe.Pointer(&result))) }()
	if result.count == 0 || result.entries == nil {
		return nil, errors.New("automatic proxy lookup returned no route")
	}
	return firstWinProxy(*result.entries)
}

func proxyLookupCallback(_ uintptr, requestID uintptr, status uint32, info unsafe.Pointer, infoLength uint32) uintptr {
	reply, ok := winProxyRequests.Load(requestID)
	if !ok {
		return 0
	}
	var result uint32
	switch status {
	case winProxyLookupComplete:
	case winProxyRequestError:
		result = uint32(windows.ERROR_GEN_FAILURE)
		if info != nil && uintptr(infoLength) >= unsafe.Sizeof(winProxyAsyncResult{}) {
			if code := (*winProxyAsyncResult)(info).err; code != 0 {
				result = code
			}
		}
	default:
		return 0
	}
	select {
	case reply.(chan uint32) <- result:
	default:
	}
	return 0
}

func firstWinProxy(entry winProxyEntry) (*url.URL, error) {
	if entry.proxy == 0 {
		return nil, nil
	}
	var scheme string
	switch entry.scheme {
	case winProxySchemeHTTP:
		scheme = "http"
	case winProxySchemeHTTPS:
		scheme = "https"
	default:
		// WinHTTP's SOCKS result does not identify the version. Go's transport
		// only speaks SOCKS5, so do not guess or switch to a later route.
		return nil, fmt.Errorf("automatic proxy selected unsupported protocol %d", entry.scheme)
	}
	host := windows.UTF16PtrToString(entry.host)
	if host == "" {
		return nil, errors.New("automatic proxy did not provide a host")
	}
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	if entry.port != 0 {
		host = net.JoinHostPort(host, strconv.Itoa(int(entry.port)))
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return parseWinProxy(scheme + "://" + host)
}

func resolveWinManualProxy(target *url.URL, servers, bypassList string) (*url.URL, error) {
	if strings.TrimSpace(servers) == "" {
		return nil, nil
	}
	bypass, err := winProxyBypass(target, bypassList)
	if err != nil || bypass {
		return nil, err
	}
	var general, socks string
	for _, item := range strings.FieldsFunc(servers, winProxySeparator) {
		protocol, server, specific := strings.Cut(item, "=")
		if !specific {
			if general == "" {
				general = item
			}
			continue
		}
		switch {
		case strings.EqualFold(protocol, target.Scheme):
			return parseWinProxy(server)
		case strings.EqualFold(protocol, "socks") && socks == "":
			socks = server
		}
	}
	if general != "" {
		return parseWinProxy(general)
	}
	if socks != "" {
		if strings.HasPrefix(strings.ToLower(socks), "socks5://") || strings.HasPrefix(strings.ToLower(socks), "socks5h://") {
			return parseWinProxy(socks)
		}
		return nil, errors.New("manual proxy selected an unsupported SOCKS protocol")
	}
	return nil, errors.New("manual proxy settings have no route for this URL")
}

func parseWinProxy(server string) (*url.URL, error) {
	if !strings.Contains(server, "://") {
		server = "http://" + server
	}
	proxy, err := url.Parse(server)
	if err != nil || proxy.Hostname() == "" || proxy.Opaque != "" || proxy.Fragment != "" ||
		proxy.ForceQuery || proxy.RawQuery != "" || (proxy.Path != "" && proxy.Path != "/") {
		return nil, errors.New("system proxy returned an invalid route")
	}
	switch proxy.Scheme {
	case "http", "https", "socks5", "socks5h":
		return proxy, nil
	default:
		return nil, errors.New("system proxy selected an unsupported protocol")
	}
}

func winProxySeparator(r rune) bool {
	return r == ';' || r == ',' || r == ' ' || r == '\t' || r == '\r' || r == '\n'
}

func winProxyBypass(target *url.URL, list string) (bool, error) {
	host := strings.TrimSuffix(strings.ToLower(target.Hostname()), ".")
	address, _ := netip.ParseAddr(host)
	port := target.Port()
	if port == "" {
		port = "80"
		if target.Scheme == "https" {
			port = "443"
		}
	}
	for _, pattern := range strings.FieldsFunc(strings.ToLower(list), winProxySeparator) {
		if pattern == "<local>" {
			if !address.IsValid() && !strings.Contains(host, ".") {
				return true, nil
			}
			continue
		}
		if scheme, rest, found := strings.Cut(pattern, "://"); found {
			if scheme != "http" && scheme != "https" && scheme != "*" {
				return false, errors.New("unsupported protocol in system proxy bypass list")
			}
			if scheme != "*" && scheme != target.Scheme {
				continue
			}
			pattern = rest
		}
		if network, err := netip.ParsePrefix(pattern); err == nil {
			if address.IsValid() && network.Contains(address) {
				return true, nil
			}
			continue
		}
		if patternHost, patternPort, err := net.SplitHostPort(pattern); err == nil {
			if patternPort != "*" && patternPort != port {
				continue
			}
			pattern = patternHost
		}
		pattern = strings.TrimSuffix(pattern, ".")
		if ip, err := netip.ParseAddr(strings.TrimSuffix(strings.TrimPrefix(pattern, "["), "]")); err == nil {
			if ip == address {
				return true, nil
			}
			continue
		}
		if pattern == "" || strings.ContainsAny(pattern, "<>:/[]?\\") {
			return false, errors.New("unsupported entry in system proxy bypass list")
		}
		if strings.HasPrefix(pattern, ".") {
			pattern = "*" + pattern
		}
		if matches, _ := path.Match(pattern, host); matches {
			return true, nil
		}
	}
	return false, nil
}
