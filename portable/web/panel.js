"use strict";

const get = (id) => document.getElementById(id);
const running = new Map();
let verified = [];

async function request(path, body) {
  const response = await fetch("api/" + path, body === undefined ? {} : {
    method: "POST",
    headers: { "Content-Type": "application/json" },
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
  get("status").textContent = result.trusted ? "Маршрут подтверждён" : "Маршрут не разрешён";
  get("status").dataset.state = result.trusted ? "trusted" : "denied";
  get("ip").textContent = (result.ips || []).join(" · ");
  list(get("providers"), [
    result.reason,
    ...(result.probes || []).map((p) => p.name + " · " + (p.ip || p.error)),
  ]);
  verified = result.trusted ? [] : (result.ips || []);
  get("trust").hidden = verified.length === 0;
}

async function refresh(first = false) {
  const state = await request("state");
  if (first) {
    const adapters = new Set(state.adapters || []);
    if (state.config.adapter) adapters.add(state.config.adapter);
    get("adapter").replaceChildren(new Option("Выберите адаптер", ""), ...[...adapters].map((name) => new Option(name, name)));
    get("adapter").value = state.config.adapter || "";
    get("allowed").value = (state.config.allowed || []).join("\n");
  }
  list(get("journal"), state.journal.filter(Boolean).reverse());
  running.clear();
  for (const [id, name] of Object.entries(state.running)) running.set(id, name);
  showRunning();
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
  get("running").replaceChildren(...[...running].map(([id, name]) => {
    const item = document.createElement("li");
    const label = document.createElement("span");
    label.textContent = name;
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
});
action("check", async () => display(await request("check", policy())));
action("trust", () => {
  get("allowed").value = [...new Set([...policy().allowed, ...verified])].join("\n");
  get("notice").textContent = "Адреса добавлены. Сохраните правило.";
});
action("save", async () => {
  await request("policy", policy());
  get("notice").textContent = "Правило сохранено.";
});
action("launch", async () => {
  const command = get("command").value.trim();
  const args = get("args").value.split("\n").filter(Boolean);
  const { id } = await request("start", { command, args });
  running.set(id, command);
  showRunning();
  get("notice").textContent = "Проверяем маршрут перед запуском.";
});
action("exit", async () => {
  await request("exit", {});
  window.location.reload();
});

refresh(true).catch((error) => { get("notice").textContent = error.message; });
setInterval(() => refresh().catch(() => {}), 2200);
