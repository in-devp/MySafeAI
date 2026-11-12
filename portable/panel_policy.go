package main

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"
)

type connectionBasics struct {
	Adapter       string   `json:"adapter"`
	Allowed       []string `json:"allowed"`
	DirectAllowed []string `json:"directAllowed"`
	Countries     []string `json:"countries"`
}

func (settings connectionBasics) apply(c *config) {
	c.Adapter, c.Allowed = settings.Adapter, settings.Allowed
	if settings.Countries != nil {
		c.Countries = settings.Countries
	}
	if settings.DirectAllowed != nil {
		c.DirectAllowed = settings.DirectAllowed
	}
}

func (p *panel) updatePolicy(update func(*config) error) (config, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	c, err := p.storage.load()
	if err != nil {
		return c, err
	}
	if err := update(&c); err != nil {
		return c, err
	}
	return c, p.storage.save(c)
}

func policyResponse(w http.ResponseWriter, c config, err error) {
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	respond(w, c)
}

func (p *panel) servePolicy(w http.ResponseWriter, r *http.Request, path string) bool {
	if r.Method != http.MethodPost {
		return false
	}
	switch path {
	case "api/policy":
		var settings connectionBasics
		if !readPanelRequest(w, r, &settings) {
			return true
		}
		c, err := p.updatePolicy(func(c *config) error { settings.apply(c); return nil })
		policyResponse(w, c, err)
	case "api/check":
		var settings connectionBasics
		if !readPanelRequest(w, r, &settings) {
			return true
		}
		c, err := p.storage.load()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return true
		}
		settings.apply(&c)
		respond(w, verify(r.Context(), c))
	case "api/diagnostics":
		c, err := p.storage.load()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return true
		}
		result := diagnoseLeaks(r.Context(), c)
		p.storage.event("Проверка утечек · DNS " + result.DNS.State)
		respond(w, result)
	case "api/watch-settings":
		var settings struct {
			Watch           bool     `json:"watch"`
			Targets         []string `json:"targets"`
			CloseAfterDelay bool     `json:"closeAfterDelay"`
			BlockOutsideDNS bool     `json:"blockOutsideDNS"`
			ObserveDNS      bool     `json:"observeDNS"`
			Notifications   bool     `json:"notifications"`
		}
		if !readPanelRequest(w, r, &settings) {
			return true
		}
		c, err := p.updatePolicy(func(c *config) error {
			c.Watch, c.Targets = &settings.Watch, append([]string{}, settings.Targets...)
			c.CloseAfterDelay, c.BlockOutsideDNS, c.ObserveDNS = settings.CloseAfterDelay, settings.BlockOutsideDNS, settings.ObserveDNS
			c.Notifications = settings.Notifications
			return nil
		})
		policyResponse(w, c, err)
	case "api/protection":
		var request struct{ Action string }
		if !readPanelRequest(w, r, &request) {
			return true
		}
		message := ""
		c, err := p.updatePolicy(func(c *config) error {
			switch request.Action {
			case "disable":
				c.ProtectionDisabled, c.ProtectionPausedUntil = true, nil
				message = "Защита отключена"
			case "pause":
				if c.protectionState(time.Now()) != "" {
					return errors.New("защита уже приостановлена или отключена")
				}
				until := time.Now().Add(15 * time.Minute)
				c.ProtectionPausedUntil = &until
				message = "Защита на паузе на 15 минут"
			case "resume":
				c.ProtectionDisabled, c.ProtectionPausedUntil = false, nil
				message = "Защита включена · проверяем подключение"
			default:
				return errors.New("неизвестное действие")
			}
			return nil
		})
		if err == nil {
			p.storage.event(message)
		}
		policyResponse(w, c, err)
	case "api/custom-target":
		var request struct {
			ID         string `json:"id"`
			Name       string `json:"name"`
			Executable string `json:"executable"`
		}
		if !readPanelRequest(w, r, &request) {
			return true
		}
		c, err := p.updatePolicy(func(c *config) error {
			if request.ID != "" {
				c.CustomTargets = slices.DeleteFunc(c.CustomTargets, func(app appTarget) bool { return app.ID == request.ID })
				c.Targets = slices.DeleteFunc(c.Targets, func(id string) bool { return id == request.ID })
				delete(c.Rules, request.ID)
				return nil
			}
			id := "custom-" + secret()[:12]
			c.CustomTargets = append(c.CustomTargets, appTarget{id, strings.TrimSpace(request.Name), strings.TrimSpace(request.Executable)})
			if c.Targets != nil {
				c.Targets = append(c.Targets, id)
			}
			return nil
		})
		policyResponse(w, c, err)
	case "api/app-rule":
		var request struct {
			ID   string             `json:"id"`
			Rule *appConnectionRule `json:"rule"`
		}
		if !readPanelRequest(w, r, &request) {
			return true
		}
		c, err := p.updatePolicy(func(c *config) error {
			if request.Rule == nil {
				delete(c.Rules, request.ID)
			} else {
				if c.Rules == nil {
					c.Rules = make(map[string]appConnectionRule)
				}
				c.Rules[request.ID] = *request.Rule
			}
			return nil
		})
		policyResponse(w, c, err)
	case "api/ip-sources":
		var request struct {
			Disabled []string           `json:"disabled"`
			Custom   []sourcePreference `json:"custom"`
		}
		if !readPanelRequest(w, r, &request) {
			return true
		}
		c, err := p.updatePolicy(func(c *config) error {
			c.DisabledSources, c.Sources = request.Disabled, request.Custom
			return nil
		})
		policyResponse(w, c, err)
	case "api/login":
		var request struct{ Enabled bool }
		if !readPanelRequest(w, r, &request) {
			return true
		}
		if err := setLoginLaunch(request.Enabled); err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
		} else {
			respond(w, request)
		}
	case "api/trusted-network":
		p.updateTrustedNetwork(w, r)
	case "api/approval":
		p.updateApproval(w, r)
	default:
		return false
	}
	return true
}

func readPanelRequest(w http.ResponseWriter, r *http.Request, request any) bool {
	if err := decode(w, r, request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return false
	}
	return true
}

func (p *panel) updateTrustedNetwork(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Name        string `json:"name"`
		Fingerprint string `json:"fingerprint"`
	}
	if !readPanelRequest(w, r, &request) {
		return
	}
	if request.Fingerprint != "" {
		c, err := p.updatePolicy(func(c *config) error {
			c.TrustedNetworks = slices.DeleteFunc(c.TrustedNetworks, func(n trustedNetwork) bool {
				return n.Fingerprint == request.Fingerprint
			})
			return nil
		})
		policyResponse(w, c, err)
		return
	}
	c, err := p.storage.load()
	if err != nil {
		policyResponse(w, c, err)
		return
	}
	network, err := captureTrustedNetwork(r.Context(), c, request.Name)
	if err != nil {
		policyResponse(w, c, err)
		return
	}
	key := policyFingerprint(c)
	c, err = p.updatePolicy(func(c *config) error {
		if policyFingerprint(*c) != key {
			return errors.New("the policy changed during the check")
		}
		c.TrustedNetworks = slices.DeleteFunc(c.TrustedNetworks, func(n trustedNetwork) bool { return n.Fingerprint == network.Fingerprint })
		c.TrustedNetworks = append(c.TrustedNetworks, network)
		return nil
	})
	policyResponse(w, c, err)
}

func captureTrustedNetwork(ctx context.Context, c config, name string) (trustedNetwork, error) {
	ctx, cancel := context.WithTimeout(ctx, 9*time.Second)
	defer cancel()
	fingerprint, adapter, err := localNetworkIdentity(ctx)
	if err != nil {
		return trustedNetwork{}, err
	}
	ipv6, err := routes(ctx, adapter)
	if err != nil {
		return trustedNetwork{}, err
	}
	addresses, err := consensus(connectionAddressProbes(ctx, c, connectionPath{mode: directRoute, adapter: adapter, ipv6: ipv6}), ipv6)
	if err != nil {
		return trustedNetwork{}, err
	}
	latest, current, err := localNetworkIdentity(ctx)
	if err != nil || latest != fingerprint || current != adapter {
		return trustedNetwork{}, errors.New("the local network changed during the check")
	}
	return trustedNetwork{strings.TrimSpace(name), fingerprint, addresses}, nil
}

func (p *panel) updateApproval(w http.ResponseWriter, r *http.Request) {
	var request struct {
		ID    string `json:"id"`
		Allow bool   `json:"allow"`
	}
	if !readPanelRequest(w, r, &request) {
		return
	}
	if p.monitor == nil {
		http.Error(w, "background protection is unavailable", http.StatusConflict)
		return
	}
	snapshot := p.monitor.snapshot()
	index := slices.IndexFunc(snapshot.Pending, func(approval pendingApproval) bool { return approval.ID == request.ID })
	if index < 0 {
		http.Error(w, "IP approval has expired", http.StatusConflict)
		return
	}
	if !request.Allow {
		p.monitor.declined.Store(request.ID, true)
		p.storage.event("IP не разрешён")
		respond(w, struct{}{})
		return
	}
	pending := snapshot.Pending[index]
	c, err := p.storage.load()
	if err != nil {
		policyResponse(w, c, err)
		return
	}
	key := policyFingerprint(c)
	fresh := verifyTarget(r.Context(), c, pending.ProbeTarget)
	if c.protectionState(time.Now()) != "" || key != pending.PolicyKey ||
		fresh.routeKey == "" || fresh.routeKey != pending.RouteKey || fresh.Mode != pending.Mode || !slices.Equal(fresh.IPs, pending.IPs) {
		http.Error(w, "the current IP or route changed, check again", http.StatusConflict)
		return
	}
	c, err = p.updatePolicy(func(c *config) error {
		if policyFingerprint(*c) != key {
			return errors.New("the policy changed during the check")
		}
		if pending.Target == "global" {
			if fresh.Mode == string(directRoute) {
				c.DirectAllowed = appendUnique(c.DirectAllowed, fresh.IPs...)
			} else {
				c.Allowed = appendUnique(c.Allowed, fresh.IPs...)
			}
		} else {
			if c.Rules == nil {
				c.Rules = make(map[string]appConnectionRule)
			}
			effective, rule := c.forTarget(pending.Target)
			rule.Allowed, rule.Countries, rule.DirectAllowed = effective.Allowed, effective.Countries, effective.DirectAllowed
			if fresh.Mode == string(directRoute) {
				rule.DirectAllowed = appendUnique(rule.DirectAllowed, fresh.IPs...)
			} else {
				rule.Allowed = appendUnique(rule.Allowed, fresh.IPs...)
			}
			c.Rules[pending.Target] = rule
		}
		return nil
	})
	if err == nil {
		p.monitor.declined.Store(request.ID, true)
		p.storage.event("IP разрешён · " + strings.Join(fresh.IPs, ", "))
	}
	policyResponse(w, c, err)
}

func appendUnique(values []string, additions ...string) []string {
	for _, value := range additions {
		if !slices.Contains(values, value) {
			values = append(values, value)
		}
	}
	return values
}
