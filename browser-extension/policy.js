/* Shared policy. No page contents, cookies, IP addresses or URLs go to the native host. */
(function (root) {
  "use strict";
  const groups = Object.freeze([
    { id: "openai", detail: "chatgpt.com · openai.com", domains: ["chatgpt.com", "openai.com"] },
    { id: "claude", detail: "claude.ai · anthropic.com", domains: ["claude.ai", "anthropic.com"] },
    { id: "cursor", detail: "cursor.com · cursor.sh", domains: ["cursor.com", "cursor.sh"] },
    { id: "gemini", detail: "gemini.google.com · aistudio.google.com", domains: ["gemini.google.com", "aistudio.google.com"] },
  ]);
  const ids = groups.map(group => group.id);
  const maxCustom = 50;
  const selected = value => Array.isArray(value) && value.every(id => ids.includes(id))
    ? ids.filter(id => value.includes(id)) : [...ids];
  const pair = (domains, action, id, priority) => [
    { id, priority, action: { type: action }, condition: { requestDomains: domains, resourceTypes: ["main_frame"] } },
    { id: id + 1, priority, action: { type: action }, condition: { requestDomains: domains, excludedResourceTypes: ["main_frame"] } },
  ];
  const rules = (wanted, action, offset, priority) => groups.flatMap((group, index) => wanted.includes(group.id)
    ? pair(group.domains, action, offset + index * 2, priority) : []);
  const contains = (parent, host) => host === parent || host.endsWith('.' + parent);
  function hostname(value) {
    try {
      const url = new URL(value);
      if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) return undefined;
      return url.hostname.toLowerCase().replace(/\.$/, "");
    } catch { return undefined; }
  }
  function groupForURL(value) {
    const host = hostname(value);
    return host ? groups.find(group => group.domains.some(domain => contains(domain, host))) : undefined;
  }
  function normalizeDomain(value) {
    if (typeof value !== 'string' || value.length > 1000) throw new Error('domainInvalid');
    const input = value.trim();
    // Accept a domain or HTTPS origin only: no credentials, ports, paths, queries or wildcards.
    const origin = input.replace(/^https:\/\//i, '').replace(/\/$/, '');
    if (!origin || /[\s\/\\:@?#*%\[\]]/.test(origin)) throw new Error('domainInvalid');
    let host;
    try { host = new URL('https://' + origin).hostname.toLowerCase().replace(/\.$/, ''); }
    catch { throw new Error('domainInvalid'); }
    if (host.length > 253 || !host.includes('.') || /^\d+(\.\d+){3}$/.test(host) ||
        /(?:^|\.)(?:localhost|local|internal|lan|home|home\.arpa|invalid|test)$/.test(host) ||
        host.split('.').some(label => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) throw new Error('domainInvalid');
    return host;
  }
  function customDomains(value) {
    if (value === undefined) return [];
    if (!Array.isArray(value) || value.length > maxCustom) throw new Error('domainLimit');
    return [...new Set(value.map(normalizeDomain))].sort();
  }
  function recoverCustomRules(value) {
    return [...new Set(value.filter(rule => rule.id >= 1000 && rule.id < 1000 + maxCustom * 2 &&
      rule.action?.type === 'block' && rule.priority === 4 && rule.condition?.requestDomains?.length === 1)
      .map(rule => normalizeDomain(rule.condition.requestDomains[0])))].sort();
  }
  function validStatus(value) {
    if (!value || value.protocol !== 1 || typeof value.allowed !== 'boolean' ||
        typeof value.reason !== 'string' || value.reason.length > 512 ||
        !['trusted', 'blocked', 'disabled', 'paused', 'unavailable'].includes(value.state)) return false;
    return value.allowed === ['trusted', 'disabled', 'paused'].includes(value.state);
  }
  const customRules = (domains, action, offset, priority) => domains.flatMap((host, index) => pair([host], action, offset + index * 2, priority));
  const api = Object.freeze({ groups, ids, maxCustom, selected, rules, groupForURL, hostname, validStatus,
    normalizeDomain, customDomains, recoverCustomRules,
    protectedURL: (url, chosen, custom) => {
      const host = hostname(url);
      return Boolean(host && (custom.some(domain => contains(domain, host)) || groups.some(group => chosen.includes(group.id) && group.domains.some(domain => contains(domain, host)))));
    },
    staticRules: () => rules(ids, 'block', 1, 1),
    excludedRules: wanted => rules(ids.filter(id => !wanted.includes(id)), 'allow', 100, 3),
    trustedRules: wanted => rules(wanted, 'allow', 200, 2),
    customBlockRules: domains => customRules(domains, 'block', 1000, 4),
    customAllowRules: domains => customRules(domains, 'allow', 2000, 6),
    sessionIDs: [...groups.flatMap((_, i) => [200 + i * 2, 201 + i * 2]), ...Array.from({length: maxCustom * 2}, (_, i) => 2000 + i)],
    dynamicIDs: [...groups.flatMap((_, i) => [100 + i * 2, 101 + i * 2]), ...Array.from({length: maxCustom * 2}, (_, i) => 1000 + i)],
  });
  root.MySafeAIPolicy = api;
  if (typeof module !== 'undefined') module.exports = api;
})(globalThis);
