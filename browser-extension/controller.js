(function (root) {
  "use strict";
  const policy = root.MySafeAIPolicy || require('./policy.js');
  const words = root.MySafeAIText || require('./i18n.js');
  const unavailable = () => ({ protocol: 1, allowed: false, state: 'unavailable', reason: '', reasonKey: 'noProof' });
  class Guard {
    constructor(api, clocks = {}) {
      this.api = api;
      this.now = clocks.now || (() => Date.now());
      this.monotonic = clocks.monotonic || (() => performance.now());
      this.state = unavailable();
      this.selected = [...policy.ids];
      this.custom = [];
      this.languagePreference = 'system';
      this.language = words.resolve('system', api.i18n?.getUILanguage() || 'en');
      this.rulesHealthy = false;
      this.edits = Promise.resolve();
      this.port = null;
      this.generation = 0;
      this.pending = null;
      this.lastReply = null;
      this.lastWall = this.now();
      this.lastMono = this.monotonic();
      this.queue = Promise.resolve();
      this.ready = false;
      this.retryAt = 0;
      this.applied = null;
    }
    text(key, values) { return words.text(key, this.language, values); }
    snapshot() { return { ...this.state, reason: this.text(this.state.reasonKey || 'reason_' + this.state.state), selected: [...this.selected], customDomains: [...this.custom], language: this.language, languagePreference: this.languagePreference, ready: this.ready, rulesHealthy: this.rulesHealthy }; }
    protects(url) { return policy.protectedURL(url, this.selected, this.custom); }
    async start() {
      // Never reuse a previous worker's permission to contact a protected site.
      await this.api.declarativeNetRequest.updateSessionRules({ removeRuleIds: policy.sessionIDs });
      const saved = await this.api.storage.local.get(['selected', 'customDomains', 'language']);
      this.selected = policy.selected(saved.selected);
      const persisted = policy.recoverCustomRules(await this.api.declarativeNetRequest.getDynamicRules());
      this.custom = policy.customDomains([...new Set([...policy.customDomains(saved.customDomains), ...persisted])]);
      this.languagePreference = ['ru', 'en'].includes(saved.language) ? saved.language : 'system';
      this.language = words.resolve(this.languagePreference, this.api.i18n?.getUILanguage() || 'en');
      this.ready = true;
      await this.syncRules(true);
      this.connect();
    }
    syncRules(force = false) {
      this.queue = this.queue.catch(() => {}).then(async () => {
        const signature = JSON.stringify([this.selected, this.custom, this.state.allowed]);
        if (!force && signature === this.applied) return;
        await this.api.declarativeNetRequest.updateSessionRules({ removeRuleIds: policy.sessionIDs });
        await this.api.declarativeNetRequest.updateDynamicRules({
          removeRuleIds: policy.dynamicIDs, addRules: [...policy.excludedRules(this.selected), ...policy.customBlockRules(this.custom)],
        });
        // Desired state may have changed while the browser was applying a rule update.
        if (this.state.allowed && this.isFresh()) {
          await this.api.declarativeNetRequest.updateSessionRules({
            removeRuleIds: policy.sessionIDs, addRules: [...policy.trustedRules(this.selected), ...policy.customAllowRules(this.custom)],
          });
        }
        this.applied = JSON.stringify([this.selected, this.custom, this.state.allowed && this.isFresh()]);
        this.rulesHealthy = true;
        if (!this.state.allowed) await this.pauseTabs();
        await this.badge();
      }).catch(async () => {
        this.state = unavailable();
        this.state.reasonKey = 'ruleFailure';
        this.rulesHealthy = false;
        this.applied = null;
        try { await this.api.declarativeNetRequest.updateSessionRules({ removeRuleIds: policy.sessionIDs }); } catch {}
        try { await this.pauseTabs(); await this.badge(); } catch {}
      });
      return this.queue;
    }
    isFresh() {
      if (!this.lastReply) return false;
      const wallAge = this.now() - this.lastReply.wall;
      const monoAge = this.monotonic() - this.lastReply.mono;
      return wallAge >= 0 && wallAge <= 2500 && monoAge >= 0 && monoAge <= 2500;
    }
    connect() {
      if (!this.ready || this.port || this.now() < this.retryAt) return;
      const generation = ++this.generation;
      try {
        const port = this.api.runtime.connectNative('app.mysafeai.browser');
        this.port = port;
        port.onMessage.addListener(value => {
          if (this.port !== port || this.generation !== generation) return;
          if (!this.pending || this.now() - this.pending.wall < 0 || this.now() - this.pending.wall > 2500 ||
              this.monotonic() - this.pending.mono > 2500 || !policy.validStatus(value)) {
            this.disconnect('invalidReply');
            return;
          }
          this.pending = null;
          this.lastReply = { wall: this.now(), mono: this.monotonic() };
          const changed = value.allowed !== this.state.allowed || value.state !== this.state.state;
          this.state = { protocol: 1, allowed: value.allowed, state: value.state, reason: value.reason };
          if (changed) void this.syncRules();
          else void this.badge();
        });
        port.onDisconnect.addListener(() => {
          // Consume Chromium's lastError without exposing native paths to the popup.
          void this.api.runtime.lastError;
          if (this.port === port && this.generation === generation) this.disconnect('openApp');
        });
        this.request();
      } catch { this.disconnect('connectFailure'); }
    }
    request() {
      if (!this.port || this.pending) return;
      this.pending = { wall: this.now(), mono: this.monotonic() };
      try { this.port.postMessage({ op: 'status' }); }
      catch { this.disconnect('disconnected'); }
    }
    disconnect(reasonKey) {
      const port = this.port;
      this.port = null;
      this.generation++;
      this.pending = null;
      this.lastReply = null;
      this.state = { ...unavailable(), reasonKey };
      this.retryAt = this.now() + 3000;
      try { port?.disconnect(); } catch {}
      if (this.ready) void this.syncRules(true);
      else this.queue = this.queue.catch(() => {}).then(() => this.api.declarativeNetRequest.updateSessionRules({ removeRuleIds: policy.sessionIDs })).catch(() => {});
    }
    async tick() {
      if (!this.ready) return;
      const wall = this.now(), mono = this.monotonic();
      const jumped = wall < this.lastWall || mono < this.lastMono || wall - this.lastWall > 2500 || mono - this.lastMono > 2500;
      this.lastWall = wall;
      this.lastMono = mono;
      if (jumped || (this.state.allowed && !this.isFresh()) ||
          (this.pending && (wall - this.pending.wall > 2500 || mono - this.pending.mono > 2500))) {
        this.disconnect('stale');
      }
      this.connect();
      this.request();
    }
    async setSelected(value) {
      if (!Array.isArray(value) || value.some(id => !policy.ids.includes(id))) throw new Error(this.text('invalidSelection'));
      const next = policy.selected(value);
      // A failed save must not make the UI claim an excluded group is now protected.
      await this.api.storage.local.set({ selected: next });
      this.selected = next;
      await this.syncRules(true);
      return this.snapshot();
    }
    async setLanguage(value) {
      if (!['system', 'ru', 'en'].includes(value)) throw new Error(this.text('invalidLanguage'));
      await this.api.storage.local.set({ language: value });
      this.languagePreference = value;
      this.language = words.resolve(value, this.api.i18n?.getUILanguage() || 'en');
      await this.badge();
      return this.snapshot();
    }
    editCustom(operation, value) {
      const edit = this.edits.catch(() => {}).then(async () => {
        let domain;
        try { domain = policy.normalizeDomain(value); }
        catch (error) { throw new Error(this.text(error.message)); }
        const previous = [...this.custom];
        if (operation === 'add' && previous.includes(domain)) throw new Error(this.text('domainExists'));
        if (operation === 'remove' && !previous.includes(domain)) throw new Error(this.text('domainMissing'));
        const next = operation === 'add' ? [...previous, domain].sort() : previous.filter(item => item !== domain);
        if (next.length > policy.maxCustom) throw new Error(this.text('domainLimit'));
        this.queue = this.queue.catch(() => {}).then(async () => {
          // A new domain is blocked persistently before any temporary grant can cover it.
          await this.api.declarativeNetRequest.updateSessionRules({ removeRuleIds: policy.sessionIDs });
          await this.api.declarativeNetRequest.updateDynamicRules({ removeRuleIds: policy.dynamicIDs,
            addRules: [...policy.excludedRules(this.selected), ...policy.customBlockRules(next)] });
          try { await this.api.storage.local.set({ customDomains: next }); }
          catch (error) {
            await this.api.declarativeNetRequest.updateDynamicRules({ removeRuleIds: policy.dynamicIDs,
              addRules: [...policy.excludedRules(this.selected), ...policy.customBlockRules(previous)] });
            throw error;
          }
          this.custom = next;
          this.applied = null;
        });
        try { await this.queue; }
        catch {
          this.state = { ...unavailable(), reasonKey: 'customFailure' };
          this.rulesHealthy = false;
          throw new Error(this.text('customFailure'));
        }
        await this.syncRules(true);
        return this.snapshot();
      });
      this.edits = edit;
      return edit;
    }
    async retry() {
      if (this.port && this.isFresh()) { this.request(); return this.snapshot(); }
      this.disconnect('checking');
      this.retryAt = 0;
      await this.queue;
      this.connect();
      return this.snapshot();
    }
    async pauseTab(tab) {
      if (this.state.allowed || !Number.isInteger(tab.id)) return;
      const destination = tab.pendingUrl || tab.url;
      if (!this.protects(destination)) return;
      // URL stays in this browser session. Never include it in the native protocol or logs.
      const key = 'paused-tab-' + tab.id;
      await this.api.storage.session.set({ [key]: destination });
      const current = await this.api.tabs.get(tab.id);
      if (this.state.allowed || (current.pendingUrl || current.url) !== destination) return;
      await this.api.tabs.update(tab.id, { url: this.api.runtime.getURL('blocked.html') });
    }
    async pauseTabs() {
      const tabs = await this.api.tabs.query({});
      await Promise.allSettled(tabs.map(tab => this.pauseTab(tab)));
    }
    async restore(tabId) {
      if (!Number.isInteger(tabId)) throw new Error(this.text('tabUnavailable'));
      const key = 'paused-tab-' + tabId;
      const stored = await this.api.storage.session.get(key);
      const url = stored[key];
      if (!policy.hostname(url)) throw new Error(this.text('noSavedURL'));
      if (this.protects(url) && (!this.state.allowed || !this.isFresh())) throw new Error(this.text('notVerified'));
      await this.queue;
      if (this.protects(url) && (!this.state.allowed || !this.isFresh())) throw new Error(this.text('notVerified'));
      const tab = await this.api.tabs.get(tabId);
      if (tab.url !== this.api.runtime.getURL('blocked.html')) throw new Error(this.text('tabChanged'));
      await this.api.tabs.update(tabId, { url });
      await this.api.storage.session.remove(key);
      return { restored: true };
    }
    async badge() {
      const off = (this.selected.length === 0 && this.custom.length === 0) || ['disabled', 'paused'].includes(this.state.state);
      await this.api.action.setBadgeText({ text: off ? 'OFF' : this.state.allowed ? '' : 'Ⅱ' });
      await this.api.action.setBadgeBackgroundColor({ color: off ? '#64748b' : this.state.allowed ? '#5db79c' : '#b77926' });
      await this.api.action.setTitle({ title: this.text(off ? 'badgeOff' : this.state.allowed ? 'badgeTrusted' : 'badgeBlocked') });
    }
  }
  root.MySafeAIGuard = Guard;
  if (typeof module !== 'undefined') module.exports = Guard;
})(globalThis);
