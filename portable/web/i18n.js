(function (root) {
  "use strict";
  let dictionaries = { ru: {}, en: {} };
  let preference = 'system';
  let language = 'en';
  let browserLanguage = 'en';
  const staticText = [];
  const staticAttributes = [];

  function configure(values) { dictionaries = values; }
  function choose(value, system = browserLanguage) {
    preference = ['ru', 'en'].includes(value) ? value : 'system';
    browserLanguage = system || 'en';
    language = preference === 'system' ? (/^ru(?:-|$)/i.test(browserLanguage) ? 'ru' : 'en') : preference;
    if (typeof document !== 'undefined') document.documentElement.lang = language;
    return language;
  }
  function translate(value, args = {}) {
    const source = String(value ?? '');
    const key = source.trim();
    const translated = dictionaries[language][key];
    let result = translated === undefined ? source : source.replace(key, () => translated);
    return result.replace(/\{([a-zA-Z]+)\}/g, (match, name) => Object.hasOwn(args, name) ? String(args[name]) : match);
  }
  function message(value) {
    const source = String(value ?? '');
    if (Object.hasOwn(dictionaries[language], source.trim())) return translate(source);
    // Some notices already rendered in the previous language are kept while
    // changing language. Match full known messages only, never arbitrary user data.
    for (const [key, text] of Object.entries(dictionaries[language === 'ru' ? 'en' : 'ru'])) {
      if (text === source.trim()) return source.replace(source.trim(), dictionaries[language][key]);
    }
    const patterns = [
      [/^the system proxy is unconfirmed for (.+)$/, 'System proxy unconfirmed for {value}'],
      [/^no route to (.+)$/, 'No route to {value}'],
      [/^service (.+) has a route outside the selected adapter$/, 'Service {value} uses a route outside the selected adapter'],
      [/^(.+) did not confirm its service route: (.+)$/, 'Service {value} did not confirm its route: {detail}'],
      [/^(.+) did not report a valid service exit IP$/, 'Service {value} did not report a valid exit IP'],
      [/^IPv4 route to (.+): (.+)$/, 'IPv4 route to {value}: {detail}'],
      [/^IPv6 route to (.+): (.+)$/, 'IPv6 route to {value}: {detail}'],
      [/^IPv4 uses (.+) instead of (.+)$/, 'IPv4 uses {value} instead of {detail}'],
      [/^IPv6 uses (.+) instead of (.+)$/, 'IPv6 uses {value} instead of {detail}'],
      [/^invalid IP or CIDR: (.+)$/, 'Invalid IP or CIDR: {value}'],
      [/^invalid direct IP: (.+)$/, 'Invalid direct IP: {value}'],
      [/^invalid country code: (.+)$/, 'Invalid country code: {value}'],
      [/^unknown protected application: (.+)$/, 'Unknown protected app: {value}'],
      [/^invalid HTTPS IP source: (.+)$/, 'Invalid HTTPS IP provider: {value}'],
      [/^unknown application rule: (.+)$/, 'Unknown app policy: {value}'],
      [/^invalid service domain for (.+)$/, 'Invalid service domain for {value}'],
      [/^unknown connection mode: (.+)$/, 'Unknown connection mode: {value}'],
      [/^rule for (.+): (.+)$/, 'Policy for {value}: {detail}'],
      [/^connection mode (.+) is unavailable for (.+)$/, 'Connection mode {value} is unavailable for {detail}'],
      [/^invalid trusted network IP: (.+)$/, 'Invalid trusted network IP: {value}'],
    ];
    for (const [pattern, key] of patterns) {
      const match = pattern.exec(source);
      if (match) return translate(key, { value: match[1], detail: match[2] ? message(match[2]) : '' });
    }
    return source;
  }
  function journal(value) {
    const match = /^(\d{4}-\d{2}-\d{2}T\S+)\s+(.*)$/.exec(value);
    const prefix = match ? match[1] + ' ' : '';
    const entry = match ? match[2] : value;
    const exact = message(entry);
    if (exact !== entry) return prefix + exact;
    const managed = /^(paused|resumed) (.+) · (.+)$/.exec(entry);
    if (managed) return prefix + translate(managed[1] === 'paused' ? 'Paused {value} · {detail}' : 'Resumed {value} · {detail}', { value: managed[2], detail: message(managed[3]) });
    const lifecycle = /^(started|exited) (.+)$/.exec(entry);
    if (lifecycle) return prefix + translate(lifecycle[1] === 'started' ? 'Started {value}' : 'Closed {value}', { value: lifecycle[2] });
    // Translate only known event prefixes. Program names, paths, IPs and
    // user-defined network names retain their original bytes.
    for (const marker of ['IP разрешён ·', 'Запрошено закрытие ·', 'На паузе ·', 'Продолжено · PID', 'Проверка утечек · DNS', 'launch error ·']) {
      if (entry.startsWith(marker)) {
        const detail = entry.slice(marker.length);
        const translatedDetail = marker === 'Проверка утечек · DNS' || marker === 'launch error ·' ? message(detail) : detail;
        return prefix + translate(marker) + translatedDetail;
      }
    }
    return prefix + entry;
  }
  function captureStatic() {
    if (typeof document === 'undefined') return;
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    while (walker.nextNode()) {
      const node = walker.currentNode;
      if (node.textContent.trim() && !['SCRIPT', 'STYLE', 'CODE'].includes(node.parentElement?.tagName)) {
        staticText.push({ node, source: node.textContent });
      }
    }
    for (const element of document.querySelectorAll('[placeholder], [aria-label], [title]')) {
      for (const name of ['placeholder', 'aria-label', 'title']) {
        if (element.hasAttribute(name)) staticAttributes.push({ element, name, source: element.getAttribute(name) });
      }
    }
  }
  function renderStatic() {
    for (const { node, source } of staticText) if (node.isConnected) node.textContent = translate(source);
    for (const { element, name, source } of staticAttributes) if (element.isConnected) element.setAttribute(name, translate(source));
  }
  const api = { configure, choose, translate, message, journal, captureStatic, renderStatic,
    get language() { return language; }, get preference() { return preference; } };
  root.PortableI18n = api;
  if (typeof module !== 'undefined') module.exports = api;
})(globalThis);
