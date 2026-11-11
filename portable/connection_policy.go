package main

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
)

type connectionMode string

const (
	fullTunnel    connectionMode = "tunnel"
	serviceTunnel connectionMode = "service"
	systemProxy   connectionMode = "proxy"
)

type appConnectionRule struct {
	Mode         connectionMode `json:"mode,omitempty"`
	Allowed      []string       `json:"allowed"`
	Countries    []string       `json:"countries"`
	TrustedLocal *bool          `json:"trustedLocal,omitempty"`
	Host         string         `json:"host,omitempty"`
}

type trustedNetwork struct {
	Name        string   `json:"name"`
	Fingerprint string   `json:"fingerprint"`
	Addresses   []string `json:"addresses"`
}

type sourcePreference struct {
	Name string `json:"name"`
	URL  string `json:"url"`
	IPv6 bool   `json:"ipv6,omitempty"`
}

func (c config) commandTargets(command []string) []string {
	var ids []string
	if preset := presetForProcess(appProcess{Executable: command[0], Arguments: command}); preset != "" {
		ids = append(ids, preset)
	}
	for _, target := range c.CustomTargets {
		if matchesExecutable(target.Executable, command[0]) {
			ids = append(ids, target.ID)
		}
	}
	if len(ids) == 0 {
		ids = []string{"managed"}
	}
	return ids
}

func validateAddresses(values []string) error {
	for _, value := range values {
		if ip, err := netip.ParseAddr(value); err == nil && ip.Zone() == "" {
			continue
		}
		if _, err := netip.ParsePrefix(value); err != nil {
			return fmt.Errorf("invalid IP or CIDR: %s", value)
		}
	}
	return nil
}

func validateCountries(values []string) error {
	for _, code := range values {
		if len(code) != 2 || code[0] < 'A' || code[0] > 'Z' || code[1] < 'A' || code[1] > 'Z' {
			return fmt.Errorf("invalid country code: %s", code)
		}
	}
	return nil
}

func addressAllowed(values []string, ip netip.Addr) bool {
	for _, value := range values {
		if address, err := netip.ParseAddr(value); err == nil && ip == address {
			return true
		}
		if prefix, err := netip.ParsePrefix(value); err == nil && prefix.Contains(ip) {
			return true
		}
	}
	return false
}

func (c config) validatePolicy() error {
	if err := errors.Join(validateAddresses(c.Allowed), validateCountries(c.Countries)); err != nil {
		return err
	}
	if len(c.CustomTargets) > 24 || len(c.TrustedNetworks) > 24 || len(c.Sources) > 16 {
		return errors.New("too many apps, networks, or IP sources")
	}
	targets := map[string]bool{"managed": true}
	for _, target := range builtInTargets {
		targets[target.ID] = true
	}
	for _, target := range c.CustomTargets {
		if !strings.HasPrefix(target.ID, "custom-") || targets[target.ID] || strings.TrimSpace(target.Name) == "" ||
			!filepath.IsAbs(target.Executable) {
			return errors.New("invalid or duplicate custom application")
		}
		targets[target.ID] = true
	}
	for _, id := range c.Targets {
		if !targets[id] || id == "managed" {
			return fmt.Errorf("unknown protected application: %s", id)
		}
	}
	for id, rule := range c.Rules {
		if !targets[id] {
			return fmt.Errorf("unknown application rule: %s", id)
		}
		switch rule.Mode {
		case "", fullTunnel:
		case serviceTunnel, systemProxy:
			if id == "managed" || len(serviceHosts(id, rule.Host)) == 0 || (rule.Mode == systemProxy && (id == "codex-cli" || id == "claude-code")) {
				return fmt.Errorf("connection mode %s is unavailable for %s", rule.Mode, id)
			}
		default:
			return fmt.Errorf("unknown connection mode: %s", rule.Mode)
		}
		if rule.Host != "" && !validServiceHost(rule.Host) {
			return fmt.Errorf("invalid service domain for %s", id)
		}
		if err := errors.Join(validateAddresses(rule.Allowed), validateCountries(rule.Countries)); err != nil {
			return fmt.Errorf("rule for %s: %w", id, err)
		}
	}
	for _, network := range c.TrustedNetworks {
		if strings.TrimSpace(network.Name) == "" || network.Fingerprint == "" || len(network.Addresses) == 0 {
			return errors.New("invalid trusted network")
		}
		for _, address := range network.Addresses {
			if ip, err := netip.ParseAddr(address); err != nil || ip.Zone() != "" {
				return fmt.Errorf("invalid trusted network IP: %s", address)
			}
		}
	}
	for _, source := range c.Sources {
		if _, err := source.provider(); err != nil {
			return err
		}
	}
	return nil
}

func (source sourcePreference) provider() (provider, error) {
	url, err := url.Parse(source.URL)
	if err != nil || url.Scheme != "https" || url.Hostname() == "" ||
		url.User != nil || url.Fragment != "" || url.RawQuery != "" || strings.TrimSpace(source.Name) == "" {
		return provider{}, fmt.Errorf("invalid HTTPS IP source: %s", source.Name)
	}
	return provider{source.Name, url.String(), source.IPv6, url.Path == "/cdn-cgi/trace"}, nil
}

func (c config) forTarget(id string) (config, appConnectionRule) {
	rule := c.Rules[id]
	if rule.Allowed != nil || rule.Countries != nil {
		c.Allowed, c.Countries = rule.Allowed, rule.Countries
	}
	if rule.TrustedLocal != nil && !*rule.TrustedLocal {
		c.TrustedNetworks = nil
	}
	if rule.Mode == "" {
		rule.Mode = fullTunnel
	}
	return c, rule
}

func (c config) activeTargets() []appTarget {
	if c.Watch != nil && !*c.Watch {
		return nil
	}
	targets := slices.Concat(builtInTargets, c.CustomTargets)
	if c.Targets == nil {
		return targets
	}
	return slices.DeleteFunc(targets, func(target appTarget) bool { return !slices.Contains(c.Targets, target.ID) })
}

func serviceHosts(id string, host string) []string {
	var hosts []string
	switch id {
	case "codex-cli":
		hosts = []string{"chatgpt.com", "api.openai.com"}
	case "codex-desktop", "chatgpt":
		hosts = []string{"chatgpt.com", "ws.chatgpt.com", "api.openai.com"}
	case "claude-code", "claude-desktop":
		hosts = []string{"claude.ai", "api.anthropic.com"}
	case "cursor":
		hosts = []string{"api2.cursor.sh"}
	}
	if host != "" && !slices.Contains(hosts, host) {
		hosts = append(hosts, host)
	}
	return hosts
}

func validServiceHost(host string) bool {
	if len(host) > 253 || !strings.Contains(host, ".") {
		return false
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return false
	}
	for label := range strings.SplitSeq(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, letter := range []byte(label) {
			if (letter < 'a' || letter > 'z') && (letter < '0' || letter > '9') && letter != '-' {
				return false
			}
		}
	}
	return true
}
