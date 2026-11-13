const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { createHash } = require('node:crypto');
const policy = require('../policy.js');
const Guard = require('../controller.js');
function event() {
  const listeners = [];
  return { addListener: callback => listeners.push(callback), emit: value => listeners.forEach(callback => callback(value)) };
}
function area(initial = {}) {
  const data = structuredClone(initial);
  return { data, get: async key => Object.fromEntries((Array.isArray(key) ? key : [key]).map(item => [item,data[item]])), set: async value => Object.assign(data, value), remove: async key => { delete data[key]; } };
}
function fixture({ selected, tabs = [] } = {}) {
  let now = 10_000, mono = 100;
  const connections = [], changes = [];
  const session = new Map(), dynamic = new Map();
  const tabMap = new Map(tabs.map(tab => [tab.id, structuredClone(tab)]));
  const api = {
    i18n: { getUILanguage: () => 'ru-RU' },
    runtime: { connectNative: name => {
      assert.equal(name, 'app.mysafeai.browser');
      const port = { onMessage: event(), onDisconnect: event(), sent: [], closed: false,
        postMessage(value) { this.sent.push(value); },
        disconnect() { this.closed = true; this.onDisconnect.emit(); } };
      connections.push(port); return port;
    }, getURL: value => 'chrome-extension://test/' + value },
    storage: { local: area(selected === undefined ? {} : { selected }), session: area() },
    declarativeNetRequest: {
      getDynamicRules: async () => [...dynamic.values()],
      updateSessionRules: async ({ removeRuleIds = [], addRules = [] }) => {
        for (const id of removeRuleIds) session.delete(id);
        for (const rule of addRules) session.set(rule.id, rule);
        changes.push(['session', [...session.values()]]);
      },
      updateDynamicRules: async ({ removeRuleIds = [], addRules = [] }) => {
        for (const id of removeRuleIds) dynamic.delete(id);
        for (const rule of addRules) dynamic.set(rule.id, rule);
        changes.push(['dynamic', [...dynamic.values()]]);
      },
    },
    tabs: {
      query: async () => [...tabMap.values()].map(tab => structuredClone(tab)),
      get: async id => structuredClone(tabMap.get(id)),
      update: async (id, changes) => Object.assign(tabMap.get(id), changes),
    },
    action: { setBadgeText: async () => {}, setBadgeBackgroundColor: async () => {}, setTitle: async () => {} },
  };
  const guard = new Guard(api, { now: () => now, monotonic: () => mono });
  const reply = async (value = { protocol: 1, state: 'trusted', allowed: true, reason: 'verified' }) => {
    connections.at(-1).onMessage.emit(value);
    await guard.queue;
  };
  return { api, guard, connections, session, dynamic, changes, tabMap, reply,
    advance(ms) { now += ms; mono += ms; }, wall(ms) { now += ms; } };
}

test('packaged static rules block main navigation, subresources and WebSocket destinations by default', () => {
  const stored = JSON.parse(fs.readFileSync(path.join(__dirname, '../rules.json')));
  assert.deepEqual(stored, policy.staticRules());
  for (const group of policy.groups) {
    const rules = stored.filter(rule => rule.condition.requestDomains === group.domains || JSON.stringify(rule.condition.requestDomains) === JSON.stringify(group.domains));
    assert.equal(rules.length, 2);
    assert.ok(rules.every(rule => rule.action.type === 'block'));
    assert.deepEqual(rules[0].condition.resourceTypes, ['main_frame']);
    assert.deepEqual(rules[1].condition.excludedResourceTypes, ['main_frame']);
  }
});
test('domain matching is precise and rejects unrelated, credential and suffix trick URLs', () => {
  assert.equal(policy.groupForURL('https://api.openai.com/v1').id, 'openai');
  assert.equal(policy.groupForURL('https://chatgpt.com./').id, 'openai');
  for (const url of ['https://notchatgpt.com/', 'https://chatgpt.com.example.org/', 'https://google.com/', 'javascript:alert(1)', 'https://user@chatgpt.com/']) {
    assert.equal(policy.groupForURL(url), undefined, url);
  }
});
test('identity and host permissions are narrow, no externally connectable bridge or proxy control', () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(__dirname, '../manifest.json')));
  const firefox = JSON.parse(fs.readFileSync(path.join(__dirname, '../manifest.firefox.json')));
  const hash = createHash('sha256').update(Buffer.from(manifest.key, 'base64')).digest().subarray(0, 16).toString('hex');
  assert.equal(hash.replace(/[0-9a-f]/g, c => String.fromCharCode(97 + parseInt(c,16))), 'akehebbcjgcamdjgjpmhepmgjjlldbik');
  assert.equal(firefox.browser_specific_settings.gecko.id, 'mysafeai@in-devp');
  assert.equal(manifest.externally_connectable, undefined);
  assert.ok(!manifest.permissions.includes('proxy'));
  assert.ok(!manifest.host_permissions.includes('<all_urls>'));
  assert.ok(!JSON.stringify(manifest).includes('localhost'));
});
test('startup revokes stale session allows and blocks only selected AI tabs', async () => {
  const f = fixture({ tabs: [{ id: 1, url: 'https://chatgpt.com/c/local' }, { id: 2, url: 'https://example.org/' }] });
  f.session.set(200, { action: { type: 'allow' } });
  await f.guard.start();
  assert.equal(f.session.size, 0);
  assert.equal(f.guard.snapshot().allowed, false);
  assert.equal(f.tabMap.get(1).url, 'chrome-extension://test/blocked.html');
  assert.equal(f.tabMap.get(2).url, 'https://example.org/');
  assert.equal(f.api.storage.session.data['paused-tab-1'], 'https://chatgpt.com/c/local');
  assert.deepEqual(f.connections[0].sent, [{ op: 'status' }]);
});
test('fresh native proof opens only selected groups and explicit exclusion persists independently', async () => {
  const f = fixture({ selected: ['openai', 'claude'] });
  await f.guard.start(); await f.reply();
  assert.equal(f.session.size, 4);
  assert.equal(f.dynamic.size, 4);
  assert.equal(f.guard.snapshot().allowed, true);
  assert.ok([...f.session.values()].every(rule => rule.action.type === 'allow' && rule.priority === 2));
  assert.deepEqual(f.connections[0].sent, [{ op: 'status' }]);
  f.connections[0].onDisconnect.emit(); await f.guard.queue;
  assert.equal(f.session.size, 0);
  assert.equal(f.dynamic.size, 4);
});
test('missing native reply removes allowance on bounded timeout and rejects delayed old messages', async () => {
  const f = fixture(); await f.guard.start(); await f.reply();
  f.advance(1000); await f.guard.tick();
  assert.equal(f.connections[0].sent.length, 2);
  f.advance(2600); await f.guard.tick(); await f.guard.queue;
  assert.equal(f.session.size, 0);
  assert.equal(f.guard.snapshot().allowed, false);
  assert.equal(f.connections[0].closed, true);
  await f.reply();
  assert.equal(f.session.size, 0);
});
test('wall clock reversal and wake gap revoke trust', async () => {
  for (const change of [f => f.wall(-1000), f => f.advance(15_000)]) {
    const f = fixture(); await f.guard.start(); await f.reply();
    change(f); await f.guard.tick(); await f.guard.queue;
    assert.equal(f.session.size, 0);
    assert.equal(f.guard.snapshot().allowed, false);
  }
});
test('unsolicited, malformed and inconsistent native replies never grant access', async () => {
  for (const value of [{ protocol: 2, allowed: true, state: 'trusted', reason: '' }, { protocol: 1, allowed: true, state: 'blocked', reason: '' }, { protocol: 1, allowed: 'true', state: 'trusted', reason: '' }, { protocol: 1, allowed: true, state: 'trusted' }]) {
    const f = fixture(); await f.guard.start(); await f.reply(value);
    assert.equal(f.session.size, 0);
    assert.equal(f.guard.snapshot().allowed, false);
  }
  const f = fixture(); await f.guard.start(); await f.reply(); await f.reply();
  assert.equal(f.session.size, 0);
});
test('manual protection pause/disable is respected only as explicit native state', async () => {
  for (const state of ['paused', 'disabled']) {
    const f = fixture(); await f.guard.start(); await f.reply({ protocol: 1, allowed: true, state, reason: 'manual' });
    assert.equal(f.session.size, 8);
    assert.equal(f.guard.snapshot().state, state);
  }
});
test('returning to a paused URL requires a fresh proof and explicit restore', async () => {
  const f = fixture({ tabs: [{ id: 3, url: 'https://claude.ai/chat/local' }] });
  await f.guard.start();
  await assert.rejects(f.guard.restore(3), /не подтверждено/);
  await f.reply();
  assert.equal(f.tabMap.get(3).url, 'chrome-extension://test/blocked.html');
  await f.guard.restore(3);
  assert.equal(f.tabMap.get(3).url, 'https://claude.ai/chat/local');
  assert.equal(f.api.storage.session.data['paused-tab-3'], undefined);
});
test('rule update failure cannot leave the controller reporting trusted', async () => {
  const f = fixture(); await f.guard.start();
  const original = f.api.declarativeNetRequest.updateSessionRules;
  f.api.declarativeNetRequest.updateSessionRules = args => {
    if (args.addRules?.length) return Promise.reject(new Error('rule API failed'));
    return original(args);
  };
  await f.reply();
  assert.equal(f.session.size, 0);
  assert.equal(f.guard.snapshot().allowed, false);
});
test('an in-flight grant is revoked if native disconnects while the browser applies it', async () => {
  const f = fixture(); await f.guard.start();
  let release;
  const original = f.api.declarativeNetRequest.updateSessionRules;
  f.api.declarativeNetRequest.updateSessionRules = async args => {
    if (args.addRules?.length) await new Promise(resolve => { release = resolve; });
    await original(args);
  };
  const granted = f.reply();
  while (!release) await new Promise(resolve => setImmediate(resolve));
  f.connections[0].onDisconnect.emit();
  release(); await granted; await f.guard.queue;
  assert.equal(f.session.size, 0);
  assert.equal(f.guard.snapshot().allowed, false);
});
test('manual recheck does not unload trusted AI tabs', async () => {
  const f = fixture(); await f.guard.start(); await f.reply();
  f.tabMap.set(5, { id: 5, url: 'https://chatgpt.com/' });
  await f.guard.retry(); await f.guard.queue;
  assert.equal(f.tabMap.get(5).url, 'https://chatgpt.com/');
  assert.equal(f.connections.length, 1);
});
test('a tab navigating away while pause is being prepared is not overwritten', async () => {
  const f = fixture(); await f.guard.start();
  f.tabMap.set(6, { id: 6, url: 'https://chatgpt.com/' });
  const original = f.api.storage.session.set;
  f.api.storage.session.set = async value => { await original(value); f.tabMap.get(6).url = 'https://example.org/'; };
  await f.guard.pauseTab({ id: 6, url: 'https://chatgpt.com/' });
  assert.equal(f.tabMap.get(6).url, 'https://example.org/');
});
test('failed preference persistence does not claim protection for an excluded group', async () => {
  const f = fixture({ selected: ['claude'] }); await f.guard.start();
  f.api.storage.local.set = async () => { throw new Error('storage failed'); };
  await assert.rejects(f.guard.setSelected(['openai', 'claude']), /storage failed/);
  assert.deepEqual(f.guard.snapshot().selected, ['claude']);
  assert.ok(f.dynamic.has(100));
});
test('custom domain validation normalizes IDN and origins and rejects local or unsafe authorities', () => {
  assert.equal(policy.normalizeDomain(' HTTPS://ExAmPle.com/ '), 'example.com');
  assert.equal(policy.normalizeDomain('пример.рф'), 'xn--e1afmkfd.xn--p1ai');
  assert.equal(policy.normalizeDomain('news.example.org.'), 'news.example.org');
  for (const value of ['', 'localhost', 'a.local', 'router.internal', 'router.home.arpa', 'sample.test', '192.168.1.1', '0x7f000001', '[::1]', '*.example.com', 'https://user@example.com', 'https://example.com:443', 'example.com/path', 'example.com?x=1', 'http://example.com', 'foo_bar.example.com', 'https://example.com/#x', 'a..example.com', 'ex%61mple.com', 'x'.repeat(1001)]) {
    assert.throws(() => policy.normalizeDomain(value), undefined, value);
  }
  assert.equal(policy.protectedURL('https://sub.example.com/path', [], ['example.com']), true);
  assert.equal(policy.protectedURL('https://notexample.com/path', [], ['example.com']), false);
  assert.equal(policy.protectedURL('https://example.com.attacker.org/path', [], ['example.com']), false);
});
test('new custom sites are persistently denied before temporary trust is granted', async () => {
  const f = fixture({ selected: [] }); await f.guard.start(); await f.reply();
  f.changes.length = 0;
  await f.guard.editCustom('add', 'https://custom.example.com/');
  assert.deepEqual(f.guard.snapshot().customDomains, ['custom.example.com']);
  assert.deepEqual(f.api.storage.local.data.customDomains, ['custom.example.com']);
  const blockIndex = f.changes.findIndex(([kind, rules]) => kind === 'dynamic' && rules.some(rule => rule.id === 1000 && rule.action.type === 'block'));
  const grantIndex = f.changes.findIndex(([kind, rules]) => kind === 'session' && rules.some(rule => rule.id === 2000 && rule.action.type === 'allow'));
  assert.ok(blockIndex >= 0 && grantIndex > blockIndex);
  assert.equal(f.dynamic.get(1000).priority, 4);
  assert.equal(f.session.get(2000).priority, 6);
  f.connections[0].onDisconnect.emit(); await f.guard.queue;
  assert.equal(f.session.size, 0);
  assert.equal(f.dynamic.get(1000).action.type, 'block');
});
test('custom rules persist across worker restart and recover a pre-save crash', async () => {
  const f = fixture();
  for (const rule of policy.customBlockRules(['persist.example.com'])) f.dynamic.set(rule.id, rule);
  // Simulate worker crash after committing the persistent deny, before saving preferences.
  await f.guard.start();
  assert.deepEqual(f.guard.snapshot().customDomains, ['persist.example.com']);
  assert.equal(f.dynamic.get(1000).action.type, 'block');
  assert.equal(f.session.size, 0);
});
test('custom block takes precedence over intentionally excluded built-in group', async () => {
  const f = fixture({ selected: [] }); await f.guard.start();
  await f.guard.editCustom('add', 'api.openai.com');
  assert.ok(f.dynamic.get(1000).priority > f.dynamic.get(100).priority);
  assert.equal(f.guard.protects('https://api.openai.com/v1'), true);
  assert.equal(f.guard.protects('https://chatgpt.com/'), false);
});
test('custom removal and normalized duplicates are deterministic and leave unrelated rule IDs alone', async () => {
  const f = fixture();
  const foreign = { id: 90001, priority: 1, action: {type:'block'}, condition:{requestDomains:['foreign.example.org']} };
  f.dynamic.set(foreign.id, foreign); await f.guard.start();
  await f.guard.editCustom('add', 'Z.example.com');
  await f.guard.editCustom('add', 'a.example.org');
  await assert.rejects(f.guard.editCustom('add', 'https://z.example.com/'), /уже добавлен/);
  assert.deepEqual(f.guard.snapshot().customDomains, ['a.example.org', 'z.example.com']);
  await f.guard.editCustom('remove', 'z.example.com');
  assert.deepEqual(f.guard.snapshot().customDomains, ['a.example.org']);
  assert.equal(f.dynamic.get(1000).condition.requestDomains[0], 'a.example.org');
  assert.equal(f.dynamic.has(1002), false);
  assert.deepEqual(f.dynamic.get(90001), foreign);
  assert.equal(new Set([...policy.dynamicIDs, ...policy.sessionIDs, ...policy.staticRules().map(rule => rule.id)]).size,
    policy.dynamicIDs.length + policy.sessionIDs.length + policy.staticRules().length);
});
test('custom domain count is bounded and invalid persisted config does not clear existing denies', async () => {
  assert.throws(() => policy.customDomains(Array.from({length:51},(_,i)=>`site${i}.example.com`)), /domainLimit/);
  const f = fixture();
  f.api.storage.local.data.customDomains = ['localhost'];
  for (const rule of policy.customBlockRules(['protected.example.com'])) f.dynamic.set(rule.id, rule);
  await assert.rejects(f.guard.start());
  f.guard.disconnect('bootFailure'); await f.guard.queue;
  assert.equal(f.dynamic.get(1000).action.type, 'block');
  assert.equal(f.session.size, 0);
});
test('Russian and English cover every interface key and system preference resolves predictably', async () => {
  const words = require('../i18n.js');
  assert.deepEqual(Object.keys(words.en).sort(), Object.keys(words.ru).sort());
  assert.equal(words.resolve('system','ru-RU'),'ru');
  assert.equal(words.resolve('system','de-DE'),'en');
  assert.equal(words.resolve('en','ru-RU'),'en');
  for (const key of Object.keys(words.en)) assert.ok(words.text(key,'en').length && words.text(key,'ru').length, key);
  const f = fixture(); await f.guard.start();
  assert.equal(f.guard.snapshot().language, 'ru');
  await f.guard.setLanguage('en');
  assert.equal(f.api.storage.local.data.language, 'en');
  assert.equal(f.guard.snapshot().reason, 'No fresh confirmation from MySafeAI.');
  await assert.rejects(f.guard.restore(1), /address was not saved/);
  await f.guard.setLanguage('system');
  assert.equal(f.guard.snapshot().language, 'ru');
});
test('storage failure when adding a custom site rolls back both rules and visible settings', async () => {
  const f = fixture(); await f.guard.start();
  f.api.storage.local.set = async () => { throw new Error('disk failed'); };
  await assert.rejects(f.guard.editCustom('add', 'custom.example.com'));
  assert.deepEqual(f.guard.snapshot().customDomains, []);
  assert.equal(f.dynamic.has(1000), false);
  assert.equal(f.guard.snapshot().allowed, false);
});
