"use strict";
const api = globalThis.browser || chrome;
let updating = false, language = MySafeAIText.resolve('system', api.i18n.getUILanguage()), customSignature = '';
const text = (key, values) => MySafeAIText.text(key, language, values);
const checks = new Map();
function localize() {
  document.documentElement.lang = language;
  for (const node of document.querySelectorAll('[data-text]')) node.textContent = text(node.dataset.text);
  for (const [id, checkbox] of checks) checkbox.setAttribute('aria-label', text('protectGroup', { name: text(id) }));
}
for (const group of MySafeAIPolicy.groups) {
  const label = document.createElement('label'); label.className = 'group';
  const details = document.createElement('div');
  const name = document.createElement('div'); name.className = 'group-name'; name.dataset.text = group.id;
  const detail = document.createElement('div'); detail.className = 'group-detail'; detail.textContent = group.detail;
  details.append(name, detail);
  const input = document.createElement('input'); input.type = 'checkbox'; input.checked = true; checks.set(group.id, input);
  input.addEventListener('change', () => mutate({ op: 'select', selected: [...checks].filter(([, value]) => value.checked).map(([id]) => id) }));
  label.append(details, input); document.getElementById('groups').append(label);
}
function showError(message) { const node = document.getElementById('error'); node.hidden = !message; node.textContent = message || ''; }
function render(state) {
  if (!state) return;
  language = state.language || language;
  localize();
  const off = (state.selected?.length === 0 && !state.customDomains?.length) || ['disabled', 'paused'].includes(state.state);
  const allowed = state.allowed === true;
  document.getElementById('status-card').dataset.tone = off ? 'off' : allowed ? 'trusted' : 'blocked';
  document.getElementById('title').textContent = text(state.rulesHealthy === false ? 'titleError' : off ? 'titleOff' : allowed ? 'titleTrusted' : 'titleBlocked');
  document.getElementById('description').textContent = state.selected?.length === 0 && !state.customDomains?.length ? text('selectedNone') : off ? text('offDetail') : allowed ? text('trustedDetail') : state.reason || text('reason_blocked');
  document.getElementById('language').value = state.languagePreference || 'system';
  if (Array.isArray(state.selected)) for (const [id, checkbox] of checks) checkbox.checked = state.selected.includes(id);
  const signature = JSON.stringify([state.customDomains, language]);
  if (signature !== customSignature) {
    customSignature = signature;
    const list = document.getElementById('custom-domains'); list.replaceChildren();
    for (const domain of state.customDomains || []) {
      const row = document.createElement('li');
      const name = document.createElement('span'); name.textContent = domain;
      const remove = document.createElement('button'); remove.className = 'remove-domain'; remove.textContent = '×'; remove.setAttribute('aria-label', text('remove', { domain }));
      remove.addEventListener('click', () => mutate({ op: 'remove-domain', domain }));
      row.append(name, remove); list.append(row);
    }
  }
}
async function mutate(message) {
  if (updating) return;
  updating = true; showError('');
  for (const el of document.querySelectorAll('button,input,select')) el.disabled = true;
  try {
    const state = await api.runtime.sendMessage(message);
    if (state?.error) throw new Error(state.error);
    render(state);
    if (message.op === 'add-domain') document.getElementById('custom-domain').value = '';
  } catch (error) { showError(error.message || text('saveFailure')); }
  finally {
    updating = false;
    for (const el of document.querySelectorAll('button,input,select')) el.disabled = false;
    await refresh();
  }
}
async function refresh() {
  if (updating) return;
  try { render(await api.runtime.sendMessage({ op: 'status' })); }
  catch { showError(text('extensionUnavailable')); }
}
document.getElementById('retry').addEventListener('click', () => mutate({ op: 'retry' }));
document.getElementById('language').addEventListener('change', event => mutate({ op: 'language', language: event.target.value }));
document.getElementById('add-domain-form').addEventListener('submit', event => { event.preventDefault(); void mutate({ op: 'add-domain', domain: document.getElementById('custom-domain').value }); });
localize(); void refresh(); setInterval(refresh, 1000);
