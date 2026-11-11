"use strict";

const get = (id) => document.getElementById(id);
const running = new Map();
let verified = [];
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

for (const button of navigation) {
  button.addEventListener("click", () => {
    showPage(button.dataset.page);
    if (button.dataset.page === "settings") {
      const title = get("settings-page").querySelector("h2");
      title.tabIndex = -1;
      title.focus();
    }
  });
}

async function request(path, body) {
  const response = await fetch("api/" + path, body === undefined ? {} : {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-MySafeAI-Token": sessionToken },
    body: JSON.stringify(body),
  });
  if (!response.ok) throw new Error((await response.text()).trim());
  return response.json();
}

function policy() {
  return {
    adapter: get("adapter").value,
    allowed: get("allowed").value.split(/[\s,;]+/).filter(Boolean),
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
  get("status").textContent = result.trusted ? "Последняя проверка · маршрут подтверждён" : "Последняя проверка · маршрут не разрешён";
  get("status").dataset.state = result.trusted ? "trusted" : "denied";
  get("ip").textContent = (result.ips || []).join(" · ");
  get("route-note").textContent = result.reason;
  get("policy-result").textContent = [result.reason, ...(result.ips || [])].join(" · ");
  get("diagnostics").hidden = !(result.probes || []).length;
  list(get("providers"), [
    ...(result.probes || []).map((p) => p.name + " · " + (p.ip || p.error)),
  ]);
  verified = result.trusted ? [] : (result.ips || []);
  get("trust").hidden = verified.length === 0;
}

async function refresh(first = false) {
  const state = await request("state");
  sessionToken = state.token;
  if (!savingWindowMode) {
    get("tray-only").checked = state.trayOnly;
    get("tray-only").disabled = !state.trayAvailable;
  }
  get("hide-window").hidden = !state.trayAvailable;
  get("pick").hidden = !state.canPick;
  get("pick-custom").hidden = !state.canPick;
  get("tray-hint").textContent = state.trayAvailable
    ? "MySafeAI запускается скрытым. Окно открывается из трея."
    : "Для этого режима нужен системный трей.";
  if (first) {
    currentTargets = state.targets || [];
    currentSources = state.sources || [];
    const adapters = new Set(state.adapters || []);
    if (state.config.adapter) adapters.add(state.config.adapter);
    get("adapter").replaceChildren(new Option("Выберите адаптер", ""), ...[...adapters].map((name) => new Option(name, name)));
    get("adapter").value = state.config.adapter || "";
    get("allowed").value = (state.config.allowed || []).join("\n");
    get("countries").value = (state.config.countries || []).join(", ");
    get("login-start").checked = state.login;
    showConfig(state.config);
  }
  displayWatch(state.watch);
  const entries = state.journal.filter(Boolean).reverse();
  get("journal-empty").hidden = entries.length !== 0;
  list(get("journal"), entries);
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
  remove.textContent = "Удалить";
  remove.setAttribute("aria-label", "Удалить " + title);
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

function showConfig(config) {
  currentConfig = config;
  pendingSources = [...(config.sources || [])];
  currentTargets = [
    ...currentTargets.filter((target) => !target.executable),
    ...(config.customTargets || []),
  ];
  const targetPicker = get("app-rule-target");
  const selected = targetPicker.value;
  targetPicker.replaceChildren(new Option("Другие команды", "managed"),
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
  const hasServices = id !== "managed" && !id.startsWith("custom-");
  const isCLI = id === "codex-cli" || id === "claude-code";
  get("app-rule-mode").value = rule.mode || "tunnel";
  get("app-rule-mode").querySelector('[value="service"]').disabled = !hasServices;
  get("app-rule-mode").querySelector('[value="proxy"]').disabled = !hasServices || isCLI;
  get("app-rule-override").checked = rule.allowed != null || rule.countries != null;
  get("app-rule-ips").value = (rule.allowed || []).join("\n");
  get("app-rule-countries").value = (rule.countries || []).join(", ");
  get("app-rule-local").checked = rule.trustedLocal !== false;
  toggleRuleFields();
}

function toggleRuleFields() {
  const enabled = get("app-rule-override").checked;
  get("app-rule-ips").disabled = !enabled;
  get("app-rule-countries").disabled = !enabled;
}

function displayWatch(state) {
  const labels = { checking: "Проверяем подключение", protected: "Доверенное подключение",
    paused: "Приложения на паузе", off: "Автообнаружение выключено", failed: "Ошибка защиты" };
  const message = [labels[state?.state], state?.message].filter(Boolean).join(" · ");
  if (get("watch-status").textContent !== message) get("watch-status").textContent = message;
  const apps = state?.apps || [];
  const current = JSON.stringify(apps);
  if (get("watched-apps").dataset.apps !== current) {
    get("watched-apps").dataset.apps = current;
    get("watched-apps").replaceChildren(...apps.map((app) => {
      const item = document.createElement("li");
      item.textContent = app.name + " · " + ({ paused: "пауза", protected: "под защитой", failed: "ошибка" })[app.state];
      item.dataset.state = app.state;
      return item;
    }));
  }
  const previousApproval = pendingApproval?.id;
  pendingApproval = state?.pending?.[0] || null;
  get("approval-card").hidden = !pendingApproval;
  if (pendingApproval) {
    if (pendingApproval.id !== previousApproval) showPage("overview");
    get("approval-ip").textContent = pendingApproval.ips.join(" · ");
    const target = currentTargets.find((item) => item.id === pendingApproval.target);
    get("approval-target").textContent = [target?.name || "Общее правило", pendingApproval.adapter].filter(Boolean).join(" · ");
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
  const labels = { checking: "Проверяем маршрут", running: "Работает", paused: "На паузе", exited: "Завершено" };
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
    button.textContent = "Остановить";
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
  verified = [];
  get("trust").hidden = true;
  get("status").textContent = "Проверьте новый маршрут";
  delete get("status").dataset.state;
  get("ip").textContent = "";
  get("providers").replaceChildren();
  get("diagnostics").hidden = true;
  get("route-note").textContent = "Выберите VPN-адаптер и проверьте маршрут.";
  get("policy-result").textContent = "";
});
async function checkRoute() {
  if (!policy().adapter) {
    showPage("policy");
    get("adapter").focus();
    return;
  }
  display(await request("check", policy()));
  if (verified.length) showPage("policy");
}
action("check", checkRoute);
action("policy-check", checkRoute);
action("trust", () => {
  get("allowed").value = [...new Set([...policy().allowed, ...verified])].join("\n");
  get("notice").textContent = "Адреса добавлены. Сохраните правило.";
});
action("save", async () => {
  showConfig(await request("policy", policy()));
  get("notice").textContent = "Правило сохранено.";
});
get("app-rule-target").addEventListener("change", showAppRule);
get("app-rule-override").addEventListener("change", toggleRuleFields);
action("save-app-rule", async () => {
  const rule = { mode: get("app-rule-mode").value, trustedLocal: get("app-rule-local").checked };
  if (get("app-rule-override").checked) {
    rule.allowed = words(get("app-rule-ips").value);
    rule.countries = words(get("app-rule-countries").value.toUpperCase());
  }
  showConfig(await request("app-rule", { id: get("app-rule-target").value, rule }));
});
action("reset-app-rule", async () => {
  showConfig(await request("app-rule", { id: get("app-rule-target").value, rule: null }));
});
action("save-network", async () => {
  const name = get("network-name").value.trim();
  if (!name) throw new Error("Введите название сети.");
  showConfig(await request("trusted-network", { name }));
  get("network-name").value = "";
});
action("save-watch", async () => {
  const targets = [...get("watch-targets").querySelectorAll("input:checked")].map((input) => input.value);
  showConfig(await request("watch-settings", {
    watch: get("watch-enabled").checked, targets, closeAfterDelay: get("close-delay").checked,
    blockOutsideDNS: get("block-dns").checked, observeDNS: get("observe-dns").checked,
    notifications: get("notifications").checked,
  }));
  get("notice").textContent = "Настройки сохранены.";
});
action("pick-custom", async () => {
  const { path } = await request("pick", {});
  if (path) get("custom-path").value = path;
});
action("add-custom", async () => {
  const name = get("custom-name").value.trim();
  const executable = get("custom-path").value.trim();
  if (!name || !executable) throw new Error("Введите название и путь к программе.");
  showConfig(await request("custom-target", { name, executable }));
  get("custom-name").value = "";
  get("custom-path").value = "";
});
action("add-source", () => {
  const name = get("source-name").value.trim();
  const url = get("source-url").value.trim();
  if (!name || !url.startsWith("https://")) throw new Error("Введите название и HTTPS-адрес.");
  pendingSources.push({ name, url, ipv6: get("source-ipv6").checked });
  showCustomSources();
  get("source-name").value = "";
  get("source-url").value = "";
  get("source-ipv6").checked = false;
});
action("save-sources", async () => {
  const disabled = [...get("ip-sources").querySelectorAll("input:not(:checked)")].map((input) => input.value);
  showConfig(await request("ip-sources", { disabled, custom: pendingSources }));
  get("notice").textContent = "Источники сохранены.";
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
  }
  await refresh();
}
action("approve-ip", () => answerApproval(true));
action("decline-ip", () => answerApproval(false));
action("leak-check", async () => {
  const result = await request("diagnostics", {});
  const dns = { tunnel: "Через выбранный VPN", outside: "Есть путь вне VPN", unknown: "Маршрут неизвестен" };
  const proxy = { proxy: "Используется", direct: "Прямое соединение", unknown: "Не подтверждён" };
  const external = { disabled: "Выключен", unconfirmed: "Резолверы не подтверждены", observed: "Резолверы получены" };
  list(get("leak-findings"), [
    "Маршрут IPv4 · " + (result.ipv4Adapter || "не обнаружен"),
    "Маршрут IPv6 · " + (result.ipv6Adapter || "не обнаружен"),
    "Системный прокси · " + proxy[result.proxy],
    "Маршруты DNS · " + dns[result.dns.state],
    ...(result.dns.servers || []).map((server) => server.address + " · " + (server.adapter || "интерфейс неизвестен")),
    "Внешний DNS-тест · " + external[result.externalDNS.status],
    ...(result.externalDNS.resolvers || []).map((resolver) => [resolver.ip, resolver.name, resolver.country].filter(Boolean).join(" · ")),
  ]);
  list(get("leak-providers"), [
    ...(result.direct || []).map((item) => "Прямой · " + item.name + " · " + (item.ip || item.error)),
    ...(result.system || []).map((item) => "Системный · " + item.name + " · " + (item.ip || item.error)),
  ]);
  get("leak-result").hidden = false;
  get("leak-result").scrollIntoView({ block: "nearest" });
});
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
  get("notice").textContent = "Проверяем маршрут перед запуском.";
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
  get("notice").textContent = "MySafeAI завершает работу.";
});

refresh(true).catch((error) => { get("notice").textContent = error.message; });
setInterval(() => refresh().catch(() => {}), 2200);
