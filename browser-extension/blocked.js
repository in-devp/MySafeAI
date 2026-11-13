"use strict";
const api = globalThis.browser || chrome;
let tabId, language = MySafeAIText.resolve('system', api.i18n.getUILanguage());
const text = key => MySafeAIText.text(key, language);
async function request(op, data = {}) { return api.runtime.sendMessage({ op, tabId, ...data }); }
function error(message) { const el = document.getElementById('error'); el.hidden = !message; el.textContent = message || ''; }
function localize() {
  document.documentElement.lang = language;
  document.title = text('pausedHeading') + ' · MySafeAI';
  for (const node of document.querySelectorAll('[data-text]')) node.textContent = text(node.dataset.text);
}
async function refresh() {
  try {
    const state = await request('status');
    const saved = await request('paused-url');
    language = state?.language || language; localize();
    const excluded = saved?.selected === false;
    const allowed = state?.allowed === true || excluded;
    document.getElementById('restore').disabled = !allowed;
    document.getElementById('language').value = state?.languagePreference || 'system';
    document.getElementById('status-card').dataset.tone = allowed ? 'trusted' : 'blocked';
    document.getElementById('status').textContent = text(allowed ? 'canReturn' : 'waiting');
    document.getElementById('reason').textContent = excluded ? text('excludedDetail') : ['disabled', 'paused'].includes(state?.state) ? text('offDetail') : allowed ? text('returnDetail') : state?.reason || text('reason_blocked');
    document.getElementById('site').textContent = saved?.hostname || text('selectedSite');
  } catch { document.getElementById('restore').disabled = true; }
}
document.getElementById('restore').addEventListener('click', async () => {
  try { const result = await request('restore'); if (result?.error) error(result.error); }
  catch { error(text('restoreFailure')); }
});
document.getElementById('retry').addEventListener('click', async () => { error(''); await request('retry').catch(() => {}); await refresh(); });
document.getElementById('language').addEventListener('change', async event => {
  const result = await request('language', { language: event.target.value }).catch(() => ({ error: text('saveFailure') }));
  if (result?.error) error(result.error);
  await refresh();
});
(async () => { tabId = (await api.tabs.getCurrent())?.id; await refresh(); })();
localize(); setInterval(refresh, 1000);
