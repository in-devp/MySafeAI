"use strict";

const get = (id) => document.getElementById(id);
const running = new Map();
let verified = [];
let sessionToken = "";
const navigation = [...document.querySelectorAll("[data-page]")];

function showPage(page) {
  for (const button of navigation) {
    const current = button.dataset.page === page;
    button.setAttribute("aria-pressed", current);
    get(button.dataset.page + "-page").hidden = !current;
  }
}

for (const button of navigation) {
  button.addEventListener("click", () => showPage(button.dataset.page));
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
  if (first) {
    const adapters = new Set(state.adapters || []);
    if (state.config.adapter) adapters.add(state.config.adapter);
    get("adapter").replaceChildren(new Option("Выберите адаптер", ""), ...[...adapters].map((name) => new Option(name, name)));
    get("adapter").value = state.config.adapter || "";
    get("allowed").value = (state.config.allowed || []).join("\n");
  }
  const entries = state.journal.filter(Boolean).reverse();
  get("journal-empty").hidden = entries.length !== 0;
  list(get("journal"), entries);
  const sessions = Object.entries(state.running);
  if (sessions.length !== running.size || sessions.some(([id, session]) => running.get(id)?.name !== session.name || running.get(id)?.state !== session.state)) {
    running.clear();
    for (const [id, session] of sessions) running.set(id, session);
    showRunning();
  }
  if (state.smoke) {
    await request("policy", { adapter: "smoke", allowed: ["203.0.113.10"] });
    await request("exit", {});
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
  await request("policy", policy());
  get("notice").textContent = "Правило сохранено.";
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
action("exit", async () => {
  await request("exit", {});
  get("notice").textContent = "MySafeAI завершает работу.";
});

refresh(true).catch((error) => { get("notice").textContent = error.message; });
setInterval(() => refresh().catch(() => {}), 2200);
