/* Chrome worker; Firefox loads policy.js and controller.js through its manifest. */
if (typeof importScripts === 'function') importScripts('policy.js', 'i18n.js', 'controller.js');
const api = globalThis.browser || chrome;
const guard = new MySafeAIGuard(api);
const boot = guard.start().catch(() => guard.disconnect('bootFailure'));
api.runtime.onMessage.addListener((message, sender, reply) => {
  const ownURL = api.runtime.getURL('');
  if (sender.id !== api.runtime.id || !sender.url?.startsWith(ownURL)) return false;
  const run = async () => {
    await boot;
    switch (message?.op) {
      case 'status':
        await guard.tick();
        return guard.snapshot();
      case 'select': return guard.setSelected(message.selected);
      case 'add-domain': return guard.editCustom('add', message.domain);
      case 'remove-domain': return guard.editCustom('remove', message.domain);
      case 'language': return guard.setLanguage(message.language);
      case 'retry': return guard.retry();
      case 'restore': return guard.restore(sender.tab?.id ?? message.tabId);
      case 'paused-url': {
        const id = sender.tab?.id ?? message.tabId;
        if (!Number.isInteger(id)) return {};
        const stored = await api.storage.session.get('paused-tab-' + id);
        const url = stored['paused-tab-' + id];
        const hostname = MySafeAIPolicy.hostname(url);
        return { hostname: hostname || '', selected: hostname ? guard.protects(url) : true };
      }
      default: throw new Error(guard.text('unknownCommand'));
    }
  };
  void run().then(reply, error => reply({ error: error.message }));
  return true;
});
api.tabs.onUpdated.addListener((id, changes, tab) => {
  if (changes.url || changes.status === 'loading') void boot.then(() => guard.pauseTab({ ...tab, id })).catch(() => {});
});
api.tabs.onRemoved.addListener(id => { void api.storage.session.remove('paused-tab-' + id); });
api.runtime.onStartup.addListener(() => { void boot.then(() => guard.retry()); });
api.runtime.onInstalled.addListener(() => { void boot.then(() => guard.retry()); });
api.alarms.onAlarm.addListener(alarm => {
  if (alarm.name === 'native-watchdog') void boot.then(() => guard.tick());
});
void api.alarms.create('native-watchdog', { periodInMinutes: 0.5 });
setInterval(() => { void guard.tick(); }, 1000);
