"use strict";

const get = (id) => document.getElementById(id);
const i18n = PortableI18n;
const t = i18n.translate;
const running = new Map();
let lastState = null;
let lastCheck = null;
let lastLeak = null;
let verified = [];
let verifiedMode = "";
let sessionToken = "";
let savingWindowMode = false;
let currentConfig = {};
let currentTargets = [];
let currentSources = [];
let pendingApproval = null;
let pendingSources = [];
const navigation = [...document.querySelectorAll("[data-page]")];

function showPage(page) {
  for (const button of navigation) {
    const current = button.dataset.page === page;
    button.setAttribute("aria-pressed", current);
    get(button.dataset.page + "-page").hidden = !current;
  }
}

function navigatePage(page) {
  showPage(page);
  if (page === "settings") {
    const title = get("settings-page").querySelector("h2");
    title.tabIndex = -1;
    title.focus();
  }
}

for (const button of navigation) {
  button.addEventListener("click", () => navigatePage(button.dataset.page));
}

document.addEventListener("keydown", (event) => {
  if ((event.ctrlKey || event.metaKey) && (event.code === "Comma" || event.key === ",") &&
      !event.altKey && !event.shiftKey && !event.repeat && !event.isComposing) {
    event.preventDefault();
    navigatePage("settings");
  }
});

async function request(path, body) {
  const response = await fetch("api/" + path, body === undefined ? {} : {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-MySafeAI-Token": sessionToken },
    body: JSON.stringify(body),
  });
  if (!response.ok) throw new Error(i18n.message((await response.text()).trim()));
  return response.json();
}

function policy() {
  return {
    adapter: get("adapter").value,
    allowed: get("allowed").value.split(/[\s,;]+/).filter(Boolean),
    directAllowed: words(get("direct-allowed").value),
    countries: words(get("countries").value.toUpperCase()),
  };
}

function list(node, lines) {
  node.replaceChildren(...lines.map((line) => {
    const item = document.createElement("li");
    item.textContent = line;
    return item;
  }));
}

function display(result) {
  lastCheck = result;
  get("status").textContent = result.trusted ? t("Последняя проверка · маршрут подтверждён") : t("Последняя проверка · маршрут не разрешён");
  get("status").dataset.state = result.trusted ? "trusted" : "denied";
  get("ip").textContent = (result.ips || []).join(" · ");
  get("route-note").textContent = i18n.message(result.reason);
  get("policy-result").textContent = [i18n.message(result.reason), ...(result.ips || [])].join(" · ");
  get("diagnostics").hidden = !(result.probes || []).length;
  list(get("providers"), [
    ...(result.probes || []).map((p) => p.name + " · " + (p.ip || i18n.message(p.error))),
  ]);
  verified = result.trusted ? [] : (result.ips || []);
  verifiedMode = result.mode;
  get("trust").hidden = verified.length === 0;
}

async function refresh(first = false) {
  const state = await request("state");
  lastState = state;
  sessionToken = state.token;
  if (first) {
    const resolved = i18n.choose(state.language?.language, navigator.language);
    i18n.renderStatic();
    get("language").value = i18n.preference;
    if (state.language?.resolved !== resolved) {
      await request("language", { language: i18n.preference, resolved });
    }
  }
  if (!savingWindowMode) {
    get("tray-only").checked = state.trayOnly;
    get("tray-only").disabled = !state.trayAvailable;
  }
  get("hide-window").hidden = !state.trayAvailable;
  get("pick").hidden = !state.canPick;
  get("pick-custom").hidden = !state.canPick;
  get("tray-hint").textContent = state.trayAvailable
    ? t("MySafeAI запускается скрытым. Окно открывается из трея.")
    : t("Для этого режима нужен системный трей.");
  if (first) {
    currentTargets = state.targets || [];
    currentSources = state.sources || [];
    const adapters = new Set(state.adapters || []);
    if (state.config.adapter) adapters.add(state.config.adapter);
    get("adapter").replaceChildren(new Option(t("Определять VPN автоматически"), ""), ...[...adapters].map((name) => new Option(name, name)));
    get("adapter").value = state.config.adapter || "";
    get("allowed").value = (state.config.allowed || []).join("\n");
    get("direct-allowed").value = (state.config.directAllowed || []).join(", ");
    get("countries").value = (state.config.countries || []).join(", ");
    get("login-start").checked = state.login;
    showConfig(state.config);
  }
  displayWatch(state.watch, state.config);
  const entries = state.journal.filter(Boolean).reverse();
  get("journal-empty").hidden = entries.length !== 0;
  list(get("journal"), entries.map(i18n.journal));
  const sessions = Object.entries(state.running);
  if (sessions.length !== running.size || sessions.some(([id, session]) => running.get(id)?.name !== session.name || running.get(id)?.state !== session.state)) {
    running.clear();
    for (const [id, session] of sessions) running.set(id, session);
    showRunning();
  }
  if (first && state.smoke) {
    await request("policy", { adapter: "smoke", allowed: ["203.0.113.10"] });
    if (state.trayAvailable) {
      await request("window-mode", { trayOnly: true });
    } else {
      const refused = await request("window-mode", { trayOnly: true }).then(() => false, () => true);
      if (!refused) throw new Error("tray-only mode must be refused without a tray");
    }
    await request("exit", {});
  }
}

function words(value) {
  return value.split(/[\s,;]+/).filter(Boolean);
}

function checkbox(id, label, checked) {
  const node = document.createElement("label");
  node.className = "setting";
  const input = document.createElement("input");
  input.type = "checkbox";
  input.value = id;
  input.checked = checked;
  node.append(input, document.createTextNode(label));
  return node;
}

function deleteRow(title, onRemove) {
  const row = document.createElement("li");
  row.className = "compact-list-item";
  const label = document.createElement("span");
  label.textContent = title;
  const remove = document.createElement("button");
  remove.className = "quiet";
  remove.dataset.removeTitle = title;
  remove.textContent = t("Удалить");
  remove.setAttribute("aria-label", t("Удалить ") + title);
  remove.addEventListener("click", async () => {
    remove.disabled = true;
    try {
      await onRemove();
    } catch (error) {
      get("notice").textContent = error.message;
    } finally {
      remove.disabled = false;
    }
  });
  row.append(label, remove);
  return row;
}

function showBrowserState(config) {
  get("browser-guide").href = "https://github.com/in-devp/MySafeAI/blob/main/docs/browser-extension" + (i18n.language === "en" ? ".en" : "") + ".md";
  get("browser-status").textContent = config.browserProtection
    ? t("Локальный компонент подключён. Установите расширение и выберите сайты в его меню. Без связи с MySafeAI выбранные сайты блокируются.")
    : t("Подключите локальный компонент, затем установите расширение из релиза.");
  get("browser-install").textContent = config.browserProtection ? t("Подключить повторно") : t("Подключить браузеры");
}

function showConfig(config) {
  currentConfig = config;
  showBrowserState(config);
  pendingSources = [...(config.sources || [])];
  currentTargets = [
    ...currentTargets.filter((target) => !target.executable),
    ...(config.customTargets || []),
  ];
  const targetPicker = get("app-rule-target");
  const selected = targetPicker.value;
  targetPicker.replaceChildren(new Option(t("Другие команды"), "managed"),
    ...currentTargets.map((target) => new Option(target.name, target.id)));
  if ([...targetPicker.options].some((option) => option.value === selected)) targetPicker.value = selected;
  showAppRule();
  get("watch-enabled").checked = config.watch !== false;
  get("close-delay").checked = Boolean(config.closeAfterDelay);
  get("block-dns").checked = Boolean(config.blockOutsideDNS);
  get("observe-dns").checked = Boolean(config.observeDNS);
  get("notifications").checked = Boolean(config.notifications);
  get("watch-targets").replaceChildren(...currentTargets.map((target) => {
    const box = checkbox(target.id, target.name, config.targets == null || config.targets.includes(target.id));
    if (!target.executable) return box;
    const row = deleteRow(target.name, async () => {
      showConfig(await request("custom-target", { id: target.id }));
    });
    row.replaceChild(box, row.firstChild);
    return row;
  }));
  get("trusted-networks").replaceChildren(...(config.trustedNetworks || []).map((network) => {
    return deleteRow(network.name, async () => {
      showConfig(await request("trusted-network", { fingerprint: network.fingerprint }));
    });
  }));
  get("ip-sources").replaceChildren(...currentSources.map((name) =>
    checkbox(name, name, !(config.disabledSources || []).includes(name))));
  showCustomSources();
}

function showCustomSources() {
  get("custom-sources").replaceChildren(...pendingSources.map((source, index) => {
    return deleteRow(source.name + " · " + source.url, () => {
      pendingSources.splice(index, 1);
      showCustomSources();
    });
  }));
}

function showAppRule() {
  const id = get("app-rule-target").value;
  const rule = currentConfig.rules?.[id] || {};
  const hasServices = id !== "managed";
  const isCLI = id === "codex-cli" || id === "claude-code";
  get("app-rule-mode").value = rule.mode || "automatic";
  get("app-rule-mode").querySelector('[value="service"]').disabled = !hasServices;
  get("app-rule-mode").querySelector('[value="proxy"]').disabled = !hasServices || isCLI;
  get("app-rule-host").value = rule.host || "";
  get("app-rule-host").disabled = !hasServices;
  get("app-rule-override").checked = rule.allowed != null || rule.countries != null || rule.directAllowed != null;
  get("app-rule-ips").value = (rule.allowed || []).join("\n");
  get("app-rule-direct").value = (rule.directAllowed || []).join(", ");
  get("app-rule-countries").value = (rule.countries || []).join(", ");
  get("app-rule-local").checked = rule.trustedLocal !== false;
  toggleRuleFields();
}

function toggleRuleFields() {
  const enabled = get("app-rule-override").checked;
  get("app-rule-ips").disabled = !enabled;
  get("app-rule-direct").disabled = !enabled;
  get("app-rule-countries").disabled = !enabled;
}

function displayWatch(state, config) {
  const deadline = new Date(config.protectionPausedUntil || 0);
  const suspended = !config.protectionDisabled && deadline > new Date();
  const inactive = suspended || config.protectionDisabled;
  get("resume-protection").hidden = !inactive;
  get("resume-protection").textContent = suspended ? t("Возобновить защиту") : t("Включить защиту");
  get("pause-protection").hidden = inactive;
  get("disable-protection").hidden = config.protectionDisabled;
  const labels = { checking: t("Проверяем подключение"), protected: t("Доверенное подключение"),
    paused: t("Приложения на паузе"), off: t("Автообнаружение выключено"), failed: t("Ошибка защиты") };
  const time = suspended ? deadline.toLocaleTimeString(i18n.language, { hour: "2-digit", minute: "2-digit" }) : "";
  const label = suspended ? t("Пауза защиты до ") + time
    : config.protectionDisabled ? t("Защита выключена")
    : labels[state?.state] || labels.checking;
  const message = [label, i18n.message(state?.message)].filter(Boolean).join(" · ");
  if (get("watch-status").textContent !== message) get("watch-status").textContent = message;
  const apps = inactive ? [] : state?.apps || [];
  const current = i18n.language + JSON.stringify(apps);
  if (get("watched-apps").dataset.apps !== current) {
    get("watched-apps").dataset.apps = current;
    get("watched-apps").replaceChildren(...apps.map((app) => {
      const item = document.createElement("li");
      item.textContent = app.name + " · " + ({ paused: t("пауза"), protected: t("под защитой"), failed: t("ошибка") })[app.state];
      item.dataset.state = app.state;
      return item;
    }));
  }
  const previousApproval = pendingApproval?.id;
  pendingApproval = inactive ? null : state?.pending?.[0] || null;
  get("approval-card").hidden = !pendingApproval;
  if (pendingApproval) {
    if (pendingApproval.id !== previousApproval) showPage("overview");
    get("approval-ip").textContent = pendingApproval.ips.join(" · ");
    const target = currentTargets.find((item) => item.id === pendingApproval.target);
    const connection = pendingApproval.mode === "direct" ? t("Прямое подключение · без VPN") : pendingApproval.adapter;
    const dns = pendingApproval.dnsBlocked ? t("Приложения ждут подтверждения маршрута DNS") : "";
    get("approval-target").textContent = [target?.name || t("Общее правило"), connection, dns].filter(Boolean).join(" · ");
  }
}

function action(id, run) {
  get(id).addEventListener("click", async () => {
    get(id).disabled = true;
    get("notice").textContent = "";
    try {
      await run();
    } catch (error) {
      get("notice").textContent = error.message;
    } finally {
      get(id).disabled = false;
    }
  });
}

function showRunning() {
  const labels = { checking: t("Проверяем маршрут"), running: t("Работает"), paused: t("На паузе"), exited: t("Завершено") };
  get("running").replaceChildren(...[...running].map(([id, session]) => {
    const item = document.createElement("li");
    const label = document.createElement("span");
    label.textContent = session.name;
    const status = document.createElement("small");
    status.textContent = labels[session.state];
    status.dataset.state = session.state;
    label.append(status);
    const button = document.createElement("button");
    button.className = "quiet";
    button.textContent = t("Остановить");
    button.addEventListener("click", async () => {
      try {
        await request("stop", { id });
        running.delete(id);
        showRunning();
      } catch (error) {
        get("notice").textContent = error.message;
      }
    });
    item.append(label, button);
    return item;
  }));
}

get("adapter").addEventListener("change", () => {
  lastCheck = null;
  verified = [];
  get("trust").hidden = true;
  get("status").textContent = t("Проверьте новый маршрут");
  delete get("status").dataset.state;
  get("ip").textContent = "";
  get("providers").replaceChildren();
  get("diagnostics").hidden = true;
  get("route-note").textContent = t("Проверьте текущее подключение.");
  get("policy-result").textContent = "";
});
async function checkRoute() {
  display(await request("check", policy()));
  if (verified.length) showPage("policy");
}
action("check", checkRoute);
action("policy-check", checkRoute);
action("trust", () => {
  if (verifiedMode === "direct") {
    get("direct-allowed").value = [...new Set([...policy().directAllowed, ...verified])].join(", ");
  } else {
    get("allowed").value = [...new Set([...policy().allowed, ...verified])].join("\n");
  }
  get("notice").textContent = t("Адреса добавлены. Сохраните правило.");
});
action("save", async () => {
  showConfig(await request("policy", policy()));
  get("notice").textContent = t("Правило сохранено.");
});
get("app-rule-target").addEventListener("change", showAppRule);
get("app-rule-override").addEventListener("change", toggleRuleFields);
action("save-app-rule", async () => {
  const rule = { mode: get("app-rule-mode").value, trustedLocal: get("app-rule-local").checked,
    host: get("app-rule-host").value.trim().toLowerCase() };
  if (get("app-rule-override").checked) {
    rule.allowed = words(get("app-rule-ips").value);
    rule.directAllowed = words(get("app-rule-direct").value);
    rule.countries = words(get("app-rule-countries").value.toUpperCase());
  }
  showConfig(await request("app-rule", { id: get("app-rule-target").value, rule }));
});
action("reset-app-rule", async () => {
  showConfig(await request("app-rule", { id: get("app-rule-target").value, rule: null }));
});
for (const name of ["disable", "pause", "resume"]) {
  action(name + "-protection", async () => {
    await request("protection", { action: name });
    await refresh();
  });
}
action("save-network", async () => {
  const name = get("network-name").value.trim();
  if (!name) throw new Error(t("Введите название сети."));
  showConfig(await request("trusted-network", { name }));
  get("network-name").value = "";
});
action("browser-install", async () => {
  showConfig(await request("browser-install", {}));
  get("notice").textContent = t("Браузеры подключены. Теперь установите расширение по инструкции и откройте его меню.");
});
action("save-watch", async () => {
  const targets = [...get("watch-targets").querySelectorAll("input:checked")].map((input) => input.value);
  showConfig(await request("watch-settings", {
    watch: get("watch-enabled").checked, targets, closeAfterDelay: get("close-delay").checked,
    blockOutsideDNS: get("block-dns").checked, observeDNS: get("observe-dns").checked,
    notifications: get("notifications").checked,
  }));
  get("notice").textContent = t("Настройки сохранены.");
});
action("pick-custom", async () => {
  const { path } = await request("pick", {});
  if (path) get("custom-path").value = path;
});
action("add-custom", async () => {
  const name = get("custom-name").value.trim();
  const executable = get("custom-path").value.trim();
  if (!name || !executable) throw new Error(t("Введите название и путь к программе."));
  showConfig(await request("custom-target", { name, executable }));
  get("custom-name").value = "";
  get("custom-path").value = "";
});
action("add-source", () => {
  const name = get("source-name").value.trim();
  const url = get("source-url").value.trim();
  if (!name || !url.startsWith("https://")) throw new Error(t("Введите название и HTTPS-адрес."));
  pendingSources.push({ name, url, ipv6: get("source-ipv6").checked });
  showCustomSources();
  get("source-name").value = "";
  get("source-url").value = "";
  get("source-ipv6").checked = false;
});
action("save-sources", async () => {
  const disabled = [...get("ip-sources").querySelectorAll("input:not(:checked)")].map((input) => input.value);
  showConfig(await request("ip-sources", { disabled, custom: pendingSources }));
  get("notice").textContent = t("Источники сохранены.");
});
get("login-start").addEventListener("change", async (event) => {
  const toggle = event.currentTarget;
  toggle.disabled = true;
  try {
    await request("login", { enabled: toggle.checked });
  } catch (error) {
    toggle.checked = !toggle.checked;
    get("notice").textContent = error.message;
  } finally {
    toggle.disabled = false;
  }
});
async function answerApproval(allow) {
  if (!pendingApproval) return;
  const result = await request("approval", { id: pendingApproval.id, allow });
  if (allow) {
    showConfig(result);
    get("adapter").value = result.adapter;
    get("allowed").value = (result.allowed || []).join("\n");
    get("direct-allowed").value = (result.directAllowed || []).join(", ");
  }
  await refresh();
}
action("approve-ip", () => answerApproval(true));
action("decline-ip", () => answerApproval(false));
action("leak-check", async () => {
  const result = await request("diagnostics", {});
  if (result.changed) {
    lastLeak = null;
    get("leak-result").hidden = true;
    throw new Error(t("Сеть изменилась во время проверки. Повторите проверку."));
  }
  displayLeak(result);
  get("leak-result").scrollIntoView({ block: "nearest" });
});
function displayLeak(result) {
  lastLeak = result;
  const dns = { tunnel: t("Через выбранный VPN"), outside: t("Есть путь вне VPN"), unknown: t("Маршрут неизвестен") };
  const proxy = { proxy: t("Используется"), direct: t("Прямое соединение"), unknown: t("Не подтверждён") };
  const external = { disabled: t("Выключен"), unconfirmed: t("Резолверы не подтверждены"), observed: t("Резолверы получены") };
  list(get("leak-findings"), [
    t("Маршрут IPv4 · ") + (result.ipv4Adapter || t("не обнаружен")),
    t("Маршрут IPv6 · ") + (result.ipv6Adapter || t("не обнаружен")),
    t("Системный прокси · ") + proxy[result.proxy],
    t("Маршруты DNS · ") + dns[result.dns.state],
    ...(result.dns.servers || []).map((server) => server.address + " · " + (server.adapter || t("интерфейс неизвестен"))),
    t("Внешний DNS-тест · ") + external[result.externalDNS.status],
    ...(result.externalDNS.resolvers || []).map((resolver) => [resolver.ip, resolver.name, resolver.country].filter(Boolean).join(" · ")),
  ]);
  list(get("leak-providers"), [
    ...(result.direct || []).map((item) => t("Прямой · ") + item.name + " · " + (item.ip || i18n.message(item.error))),
    ...(result.system || []).map((item) => t("Системный · ") + item.name + " · " + (item.ip || i18n.message(item.error))),
  ]);
  get("leak-result").hidden = false;
}
action("pick", async () => {
  const { path } = await request("pick", {});
  if (path) get("command").value = path;
});
action("launch", async () => {
  const command = get("command").value.trim();
  const args = get("args").value.split("\n").filter(Boolean);
  const { id } = await request("start", { command, args });
  running.set(id, { name: command, state: "checking" });
  showRunning();
  get("notice").textContent = t("Проверяем маршрут перед запуском.");
});
action("hide-window", () => request("hide", {}));
get("tray-only").addEventListener("change", async (event) => {
  const toggle = event.currentTarget;
  const enabled = toggle.checked;
  savingWindowMode = true;
  toggle.disabled = true;
  get("notice").textContent = "";
  try {
    await request("window-mode", { trayOnly: enabled });
  } catch (error) {
    toggle.checked = !enabled;
    get("notice").textContent = error.message;
  } finally {
    savingWindowMode = false;
    toggle.disabled = false;
  }
});
action("exit", async () => {
  await request("exit", {});
  get("notice").textContent = t("MySafeAI завершает работу.");
});

function renderLanguage() {
  const notice = get("notice").textContent;
  i18n.renderStatic();
  get("language").value = i18n.preference;
  const automatic = get("adapter").querySelector('option[value=""]');
  if (automatic) automatic.textContent = t("Определять VPN автоматически");
  const managed = get("app-rule-target").querySelector('option[value="managed"]');
  if (managed) managed.textContent = t("Другие команды");
  for (const button of document.querySelectorAll('[data-remove-title]')) {
    button.textContent = t("Удалить");
    button.setAttribute("aria-label", t("Удалить ") + button.dataset.removeTitle);
  }
  showBrowserState(currentConfig);
  showRunning();
  if (lastState) {
    displayWatch(lastState.watch, lastState.config);
    list(get("journal"), lastState.journal.filter(Boolean).reverse().map(i18n.journal));
    get("tray-hint").textContent = lastState.trayAvailable
      ? t("MySafeAI запускается скрытым. Окно открывается из трея.")
      : t("Для этого режима нужен системный трей.");
  }
  if (lastCheck) display(lastCheck);
  else for (const id of ["status", "route-note"]) get(id).textContent = i18n.message(get(id).textContent);
  if (lastLeak) displayLeak(lastLeak);
  get("notice").textContent = i18n.message(notice);
}

get("language").addEventListener("change", async (event) => {
  const select = event.currentTarget;
  const previous = i18n.preference;
  select.disabled = true;
  const resolved = i18n.choose(select.value, navigator.language);
  try {
    await request("language", { language: i18n.preference, resolved });
    renderLanguage();
  } catch (error) {
    i18n.choose(previous, navigator.language);
    renderLanguage();
    get("notice").textContent = i18n.message(error.message);
  } finally {
    select.disabled = false;
  }
});

async function start() {
  const response = await fetch("locales.json");
  if (!response.ok) throw new Error("Unable to load language resources");
  i18n.configure(await response.json());
  i18n.captureStatic();
  i18n.choose("system", navigator.language);
  i18n.renderStatic();
  await refresh(true);
  setInterval(() => refresh().catch(() => {}), 2200);
}
start().catch((error) => { get("notice").textContent = error.message; });
