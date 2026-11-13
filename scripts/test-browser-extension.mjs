// Real Chromium / DNR integration check. Uses an isolated profile and a local
// fixture server; no requests to AI services or user browser settings.
// Usage: node scripts/test-browser-extension.mjs /path/to/chromium [extension]
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
import { mkdtemp, rm, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

const executable = process.argv[2];
if (!executable) throw new Error('Provide a Chromium executable that supports --load-extension');
const extension = path.resolve(process.argv[3] || 'dist/browser-extension/chromium');
const profile = await mkdtemp(path.join(tmpdir(), 'mysafeai-extension-'));
const nativeHost = process.platform === 'linux' && process.argv[4] ? path.resolve(process.argv[4]) : null;
const isolatedConfig = path.join(profile, 'native-config');
let nativeState = { allowed: false, state: 'blocked' };
let nativeHeartbeat;
let nativeWrite = Promise.resolve();
async function publishNative() {
  const now = Date.now();
  const state = { protocol: 1, ...nativeState, updatedAt: now, validUntil: now + 2500 };
  nativeWrite = nativeWrite.then(async () => {
    const temporary = path.join(isolatedConfig, 'MySafeAI', 'next.json');
    await writeFile(temporary, JSON.stringify(state));
    const { rename } = await import('node:fs/promises');
    await rename(temporary, path.join(isolatedConfig, 'MySafeAI', 'browser-state.json'));
  });
  return nativeWrite;
}
if (nativeHost) {
  await mkdir(path.join(isolatedConfig, 'MySafeAI'), { recursive: true });
  for (const browser of ['chromium', 'google-chrome', 'google-chrome-for-testing']) {
    const directory = path.join(isolatedConfig, browser, 'NativeMessagingHosts');
    await mkdir(directory, { recursive: true });
    await writeFile(path.join(directory, 'app.mysafeai.browser.json'), JSON.stringify({
      name: 'app.mysafeai.browser', description: 'MySafeAI isolated test host',
      path: nativeHost, type: 'stdio', allowed_origins: ['chrome-extension://akehebbcjgcamdjgjpmhepmgjjlldbik/'],
    }));
  }
  await publishNative();
  nativeHeartbeat = setInterval(() => { void publishNative(); }, 500);
}
const hits = [];
const server = createServer((request, response) => {
  hits.push(request.headers.host + request.url);
  response.writeHead(200, { 'Content-Type': 'text/html', 'Cache-Control': 'no-store' });
  response.end('<!doctype html><title>MySafeAI network fixture</title><p>Local fixture loaded</p>');
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const port = server.address().port;
const child = spawn(executable, [
  '--headless=new', '--remote-debugging-port=0', `--user-data-dir=${profile}`,
  // Only the disposable CI browser opts out of Linux user-namespace sandboxing.
  // Ubuntu runner policies can deny it; installed user browsers are unchanged.
  ...(process.platform === 'linux' && process.env.MYSAFEAI_TEST_NO_SANDBOX === '1' ? ['--no-sandbox'] : []),
  `--disable-extensions-except=${extension}`, `--load-extension=${extension}`,
  '--no-first-run', '--no-default-browser-check', '--disable-background-networking',
  '--no-proxy-server', '--disable-component-update', '--disable-sync',
  '--host-resolver-rules=MAP chatgpt.com 127.0.0.1, MAP chatgpt.com. 127.0.0.1, MAP unrelated.test 127.0.0.1, MAP custom.example.com 127.0.0.1, MAP custom.example.com. 127.0.0.1',
], { stdio: ['ignore', 'ignore', 'pipe'], env: { ...process.env, ...(nativeHost ? { XDG_CONFIG_HOME: isolatedConfig } : {}) } });
let socket;
const pending = new Map();
let sequence = 0;
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
async function eventually(fn, message, timeout = 8000) {
  const end = Date.now() + timeout;
  while (Date.now() < end) {
    if (await fn()) return;
    await delay(50);
  }
  throw new Error(message);
}
try {
  const endpoint = await new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error('Chromium did not start')), 15000);
    let output = '';
    child.stderr.on('data', chunk => {
      output += chunk.toString();
      const match = /DevTools listening on (ws:\/\/[^\s]+)/.exec(output);
      if (match) { clearTimeout(timeout); resolve(match[1]); }
    });
    child.once('error', reject);
    child.once('exit', (code, signal) => {
      clearTimeout(timeout);
      reject(new Error(`Chromium exited: ${code ?? signal}\n${output.slice(-8000)}`));
    });
  });
  socket = new WebSocket(endpoint);
  await new Promise((resolve, reject) => { socket.onopen = resolve; socket.onerror = reject; });
  socket.onmessage = event => {
    const message = JSON.parse(event.data);
    if (!message.id) return;
    const request = pending.get(message.id);
    if (!request) return;
    pending.delete(message.id);
    clearTimeout(request.timeout);
    if (message.error) request.reject(new Error(message.error.message));
    else request.resolve(message.result);
  };
  const call = (method, params = {}, sessionId) => new Promise((resolve, reject) => {
    const id = ++sequence;
    const timeout = setTimeout(() => { pending.delete(id); reject(new Error(`CDP timeout: ${method}`)); }, 10000);
    pending.set(id, { resolve, reject, timeout });
    socket.send(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }));
  });
  let worker;
  await eventually(async () => {
    worker = (await call('Target.getTargets')).targetInfos.find(target => target.type === 'service_worker' && target.url === 'chrome-extension://akehebbcjgcamdjgjpmhepmgjjlldbik/background.js');
    return Boolean(worker);
  }, 'Extension service worker did not start');
  assert.ok(worker.url.startsWith('chrome-extension://akehebbcjgcamdjgjpmhepmgjjlldbik/'), worker.url);
  const { sessionId } = await call('Target.attachToTarget', { targetId: worker.targetId, flatten: true });
  const evaluate = async expression => {
    const result = await call('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true }, sessionId);
    if (result.exceptionDetails) throw new Error(result.exceptionDetails.exception?.description || result.exceptionDetails.text);
    return result.result.value;
  };
  await eventually(() => evaluate("typeof boot !== 'undefined'"), 'Extension background script did not initialize');
  await evaluate('boot');
  assert.equal((await evaluate('guard.snapshot()')).allowed, false);
  await call('Target.createTarget', { url: `http://unrelated.test:${port}/unrelated` });
  await eventually(() => hits.some(hit => hit.endsWith('/unrelated')), 'Unrelated tab was blocked');
  await call('Target.createTarget', { url: `http://chatgpt.com:${port}/protected` });
  await eventually(async () => (await call('Target.getTargets')).targetInfos.some(target => target.url.endsWith('/blocked.html')), 'Protected tab did not show the pause page');
  assert.equal(hits.some(hit => hit.endsWith('/protected')), false, 'Blocked request reached the fixture');

  // Replace only the native endpoint in this test worker. Real DNR, tabs and
  // storage APIs remain live. Native framing and lease validation have Go tests.
  if (nativeHost) {
    nativeState = { allowed: true, state: 'trusted' };
    await publishNative();
    await evaluate('guard.request()');
  } else await evaluate(`(() => {
    globalThis.fixtureStatus = {protocol:1,allowed:true,state:'trusted',reason:'Fixture connection'};
    guard.api = {...api, runtime: {...api.runtime, connectNative: () => {
      let listener;
      return {onMessage:{addListener:fn => listener=fn}, onDisconnect:{addListener:() => {}},
        disconnect:() => {}, postMessage:() => queueMicrotask(() => listener({...fixtureStatus}))};
    }}};
    guard.disconnect('Test fixture'); guard.retryAt=0;
    return guard.retry();
  })()`);
  await eventually(async () => (await evaluate('guard.snapshot()')).allowed, 'Fresh native fixture was not admitted');
  await evaluate('guard.queue');
  const paused = await evaluate(`chrome.tabs.query({}).then(tabs => tabs.find(tab => tab.url === chrome.runtime.getURL('blocked.html')).id)`);
  await evaluate(`guard.restore(${paused})`);
  await eventually(() => hits.some(hit => hit.endsWith('/protected')), 'Trusted site did not resume');
  const beforeBlock = hits.filter(hit => hit.endsWith('/protected')).length;
  if (nativeHost) {
    nativeState = { allowed: false, state: 'blocked' };
    await publishNative();
    await evaluate('guard.request()');
  } else await evaluate(`fixtureStatus={protocol:1,allowed:false,state:'blocked',reason:'Fixture disconnected'}; guard.request()`);
  await eventually(async () => !(await evaluate('guard.snapshot()')).allowed, 'Native denial did not revoke permission');
  await evaluate('guard.queue');
  assert.equal((await evaluate('chrome.declarativeNetRequest.getSessionRules()')).length, 0);
  await call('Target.createTarget', { url: `http://chatgpt.com:${port}/protected` });
  await delay(300);
  assert.equal(hits.filter(hit => hit.endsWith('/protected')).length, beforeBlock, 'Revoked permission still sent a request');
  await call('Target.createTarget', { url: `http://unrelated.test:${port}/still-works` });
  await eventually(() => hits.some(hit => hit.endsWith('/still-works')), 'Unrelated site stopped after a denial');

  await evaluate("guard.editCustom('add', 'custom.example.com')");
  await evaluate('guard.queue');
  const customRules = await evaluate('chrome.declarativeNetRequest.getDynamicRules()');
  assert.ok(customRules.some(rule => rule.action.type === 'block' && rule.condition.requestDomains?.includes('custom.example.com')), 'Custom site has no persistent deny rule');
  await call('Target.createTarget', { url: `http://custom.example.com:${port}/custom-blocked` });
  await delay(300);
  assert.equal(hits.some(hit => hit.endsWith('/custom-blocked')), false, 'Custom site bypassed its block');
  await call('Target.createTarget', { url: `http://custom.example.com.:${port}/custom-trailing-dot` });
  await call('Target.createTarget', { url: `http://chatgpt.com.:${port}/preset-trailing-dot` });
  await delay(300);
  assert.equal(hits.some(hit => hit.endsWith('/custom-trailing-dot') || hit.endsWith('/preset-trailing-dot')), false, 'Trailing-dot domain bypassed a block');
  await evaluate("guard.setLanguage('en')");
  assert.equal((await evaluate('guard.snapshot()')).language, 'en');

  const popup = await call('Target.createTarget', { url: 'chrome-extension://akehebbcjgcamdjgjpmhepmgjjlldbik/popup.html' });
  const popupSession = (await call('Target.attachToTarget', { targetId: popup.targetId, flatten: true })).sessionId;
  await call('Emulation.setDeviceMetricsOverride', { width: 360, height: 650, deviceScaleFactor: 1, mobile: false }, popupSession);
  await eventually(async () => {
    const result = await call('Runtime.evaluate', { expression: "document.documentElement.lang === 'en' && document.body.innerText.includes('custom.example.com')", returnByValue: true }, popupSession);
    return result.result.value;
  }, 'English popup did not render the custom domain');
  const screenshot = await call('Page.captureScreenshot', { format: 'png' }, popupSession);
  await mkdir('dist', { recursive: true });
  await writeFile('dist/browser-popup.png', Buffer.from(screenshot.data, 'base64'));
  console.log(`PASS: real Chromium static deny, unrelated tab, ${nativeHost ? 'real native bridge' : 'native fixture'} grant/revoke, manual restore, persistent custom domain, English popup`);
} finally {
  clearInterval(nativeHeartbeat);
  await nativeWrite;
  for (const request of pending.values()) clearTimeout(request.timeout);
  socket?.close();
  child.kill('SIGTERM');
  await Promise.race([new Promise(resolve => child.once('exit', resolve)), delay(2000)]);
  if (child.exitCode === null) child.kill('SIGKILL');
  await new Promise(resolve => server.close(resolve));
  await rm(profile, { recursive: true, force: true });
}
