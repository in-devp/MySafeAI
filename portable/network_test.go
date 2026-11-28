package main

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"
)

func TestIPLookupRetriesOnlyTemporaryTransportFailure(t *testing.T) {
	invalid := errors.New("invalid provider response")
	for _, tc := range []struct {
		name   string
		first  error
		cancel bool
		calls  int
	}{
		{name: "first request succeeds", calls: 1},
		{name: "transport fails", first: errHTTPSTransport, calls: 2},
		{name: "response rejected", first: invalid, calls: 1},
		{name: "network check invalidated", first: errHTTPSTransport, cancel: true, calls: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, stop := context.WithTimeout(t.Context(), 7*time.Second)
			defer stop()
			calls := 0
			data, err := retryAddressRequest(ctx, func(attempt context.Context) ([]byte, error) {
				calls++
				if calls == 1 {
					if deadline, ok := attempt.Deadline(); !ok || time.Until(deadline) > 2*time.Second {
						t.Fatal("the first request is missing its shorter deadline")
					}
					if tc.cancel {
						stop()
					}
					if tc.first != nil {
						return nil, tc.first
					}
				} else if attempt != ctx {
					t.Fatal("retry lost the original deadline and cancellation")
				}
				return []byte("203.0.113.42"), nil
			})
			if calls != tc.calls || (tc.calls == 2 || tc.first == nil) && (err != nil || string(data) != "203.0.113.42") {
				t.Fatalf("requests=%d, result=%q, error=%v", calls, data, err)
			}
			if tc.calls == 1 && tc.first != nil && !errors.Is(err, tc.first) {
				t.Fatalf("expected first error %v, got %v", tc.first, err)
			}
		})
	}
}

func TestSelectsOneIPProviderPerAvailableFamily(t *testing.T) {
	custom := []sourcePreference{
		{Name: "Custom v4", URL: "https://example.com/ip"},
		{Name: "Second v4", URL: "https://example.net/ip"},
		{Name: "Custom v6", URL: "https://ipv6.example.com/ip", IPv6: true},
	}
	for _, tc := range []struct {
		name   string
		config config
		ipv6   bool
		want   []string
	}{
		{name: "default IPv4", want: []string{"ipify"}},
		{name: "default dual stack", ipv6: true, want: []string{"ipify", "ipify IPv6"}},
		{name: "custom source takes priority", config: config{Sources: custom}, ipv6: true, want: []string{"Custom v4", "Custom v6"}},
		{name: "IPv4 only skips custom IPv6", config: config{Sources: custom}, want: []string{"Custom v4"}},
		{name: "respects disabled sources", config: config{DisabledSources: []string{"ipify", "ipify IPv6"}}, ipv6: true, want: []string{"Cloudflare", "ident.me IPv6"}},
		{name: "all built-ins disabled", config: config{DisabledSources: sourceNames()}, ipv6: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var names []string
			for _, source := range selectedAddressProviders(tc.config, tc.ipv6) {
				names = append(names, source.name)
			}
			if !slices.Equal(names, tc.want) {
				t.Fatalf("got %v, want %v", names, tc.want)
			}
		})
	}
}
