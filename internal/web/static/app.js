"use strict";

const state = { token: "", inbound: null, loginPath: "/auth/login", pendingDelete: null, qrEmail: null, clients: [], users: null, items: [], active: -1 };
const NAME_RE = /^[a-z0-9][a-z0-9_-]{2,31}$/;
const $ = (id) => document.getElementById(id);

function readToken() {
  try {
    const raw = localStorage.getItem("sessionStore");
    return raw ? (JSON.parse(raw).state || {}).token || "" : "";
  } catch {
    return "";
  }
}

async function api(path, options = {}) {
  const resp = await fetch("api/" + path, {
    ...options,
    headers: { "Authorization": "Bearer " + state.token, "Content-Type": "application/json", ...(options.headers || {}) },
  });
  if (resp.status === 401 || resp.status === 403) {
    location.assign(state.loginPath);
    throw new Error("unauthorized");
  }
  if (!resp.ok) {
    let message = resp.statusText;
    try { message = (await resp.json()).error || message; } catch { /* not json */ }
    throw new Error(message);
  }
  return resp;
}

function showError(err) {
  $("error").textContent = err ? String(err.message || err) : "";
}

function inboundPath() {
  return "inbounds/" + encodeURIComponent(state.inbound.profile) + "/" + encodeURIComponent(state.inbound.tag) + "/clients";
}

function cell(text, className) {
  const td = document.createElement("td");
  td.textContent = text;
  if (className) td.className = className;
  return td;
}

function iconButton(label, icon, className, onClick) {
  const b = document.createElement("button");
  b.className = "btn" + (className ? " " + className : "");
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  const use = document.createElementNS("http://www.w3.org/2000/svg", "use");
  use.setAttribute("href", "#i-" + icon);
  svg.appendChild(use);
  b.appendChild(svg);
  b.appendChild(document.createTextNode(label));
  b.addEventListener("click", onClick);
  return b;
}

async function loadClients() {
  showError(null);
  const body = $("clients");
  body.replaceChildren();
  if (!state.inbound) return;
  const list = await (await api(inboundPath())).json();
  state.clients = list;
  for (const c of list) {
    const tr = document.createElement("tr");
    tr.appendChild(cell(c.username || "—"));
    tr.appendChild(cell(c.email, "mono"));
    tr.appendChild(cell(c.address, "mono"));
    const badge = document.createElement("span");
    badge.className = "badge " + (c.managed ? "ok" : "muted");
    badge.textContent = c.managed ? "сервис" : "вручную";
    const td = document.createElement("td");
    td.appendChild(badge);
    tr.appendChild(td);
    const actions = document.createElement("td");
    actions.className = "actions";
    if (c.managed) actions.appendChild(iconButton("QR", "qrcode", "", () => openQR(c)));
    actions.appendChild(iconButton("Удалить", "trash", "danger", () => askDelete(c)));
    tr.appendChild(actions);
    body.appendChild(tr);
  }
}

async function loadInbounds() {
  const list = await (await api("inbounds")).json();
  const select = $("inbound");
  select.replaceChildren();
  list.forEach((inb, i) => {
    const o = document.createElement("option");
    o.value = String(i);
    o.textContent = inb.profile + " / " + inb.tag + " — " + inb.endpoint + ", свободно " + inb.free;
    select.appendChild(o);
  });
  // Keep the current selection across reloads; the free-address count changes after edits.
  const keep = state.inbound;
  const idx = keep ? list.findIndex((x) => x.profile === keep.profile && x.tag === keep.tag) : -1;
  state.inbound = list[Math.max(idx, 0)] || null;
  select.value = String(Math.max(idx, 0));
  select.onchange = () => { state.inbound = list[Number(select.value)]; loadClients().catch(showError); };
}

async function openQR(c) {
  state.qrEmail = c.email;
  $("qr-title").textContent = (c.username || c.email) + " — " + c.address;
  const svg = await (await api(inboundPath() + "/" + encodeURIComponent(c.email) + "/qr.svg")).blob();
  const previous = $("qr-img").src;
  $("qr-img").src = URL.createObjectURL(svg);
  if (previous.startsWith("blob:")) URL.revokeObjectURL(previous);
  $("qr-dialog").showModal();
}

async function downloadConfig() {
  const resp = await api(inboundPath() + "/" + encodeURIComponent(state.qrEmail) + "/config");
  const url = URL.createObjectURL(await resp.blob());
  const a = document.createElement("a");
  a.href = url;
  a.download = "wg-" + state.qrEmail + ".conf";
  a.click();
  // Firefox may not start the download before an immediate revoke.
  setTimeout(() => URL.revokeObjectURL(url), 10000);
}

function askDelete(c) {
  state.pendingDelete = c;
  $("confirm-text").textContent = (c.username || c.email) + " (" + c.address + ")";
  $("confirm").showModal();
}

// Suggestions for the user field: panel users filtered by the input, plus
// an item to create a new user when the name is free and valid.
function buildItems(query) {
  const q = query.trim().toLowerCase();
  const users = state.users || [];
  const taken = new Set(state.clients.map((c) => c.email));
  const items = users
    .filter((u) => !q || u.username.toLowerCase().includes(q) || String(u.id) === q)
    .sort((a, b) => a.username.localeCompare(b.username))
    .slice(0, 8)
    .map((u) => {
      const has = taken.has(String(u.id));
      const meta = ["id " + u.id];
      if (u.status && u.status !== "ACTIVE") meta.push(u.status.toLowerCase());
      if (has) meta.push("уже есть клиент");
      return { value: u.username, title: u.username, meta: meta.join(" · "), disabled: has };
    });
  const exact = users.some((u) => u.username.toLowerCase() === q || String(u.id) === q);
  if (q && !exact) {
    if (NAME_RE.test(q)) {
      items.push({ value: q, title: "Создать пользователя «" + q + "»", meta: "новый пользователь панели" });
    } else if (!/^\d+$/.test(q)) {
      items.push({ hint: true, title: "Имя: строчные латинские буквы, цифры, - и _, от 3 до 32 символов" });
    }
  }
  if (!items.length) items.push({ hint: true, title: q ? "Ничего не найдено" : "Пользователей пока нет" });
  return items;
}

function selectable(i) {
  const it = state.items[i];
  return it && !it.hint && !it.disabled;
}

function renderSuggest() {
  const list = $("suggest");
  list.replaceChildren();
  state.items.forEach((it, i) => {
    const li = document.createElement("li");
    li.setAttribute("role", "option");
    li.className = (it.hint ? "hint" : "") + (it.disabled ? " disabled" : "") + (i === state.active ? " active" : "");
    li.setAttribute("aria-selected", String(i === state.active));
    const title = document.createElement("span");
    title.textContent = it.title;
    li.appendChild(title);
    if (it.meta) {
      const meta = document.createElement("span");
      meta.className = "meta";
      meta.textContent = it.meta;
      li.appendChild(meta);
    }
    // mousedown keeps focus in the field, so blur does not close the list first
    li.addEventListener("mousedown", (e) => {
      e.preventDefault();
      if (selectable(i)) choose(i);
    });
    list.appendChild(li);
  });
  list.classList.remove("hidden");
  $("user").setAttribute("aria-expanded", "true");
}

async function openSuggest() {
  if (!state.users) state.users = await (await api("users")).json();
  if (document.activeElement !== $("user")) return;
  state.items = buildItems($("user").value);
  state.active = -1;
  renderSuggest();
}

function closeSuggest() {
  $("suggest").classList.add("hidden");
  $("user").setAttribute("aria-expanded", "false");
  state.active = -1;
}

function choose(i) {
  $("user").value = state.items[i].value;
  closeSuggest();
}

function onUserKey(e) {
  const open = !$("suggest").classList.contains("hidden");
  if (e.key === "ArrowDown" || e.key === "ArrowUp") {
    e.preventDefault();
    if (!open) {
      openSuggest().catch(showError);
      return;
    }
    const step = e.key === "ArrowDown" ? 1 : -1;
    for (let n = 0, i = state.active; n < state.items.length; n++) {
      i = (i + step + state.items.length) % state.items.length;
      if (selectable(i)) {
        state.active = i;
        break;
      }
    }
    renderSuggest();
  } else if (e.key === "Escape") {
    closeSuggest();
  } else if (e.key === "Enter") {
    e.preventDefault();
    if (open && selectable(state.active)) {
      choose(state.active);
    } else if (!$("add").disabled) {
      closeSuggest();
      addClient().catch(showError);
    }
  }
}

async function addClient() {
  const user = $("user").value.trim();
  if (!user) {
    showError("Укажите id или имя пользователя панели, для которого создать клиента.");
    $("user").focus();
    return;
  }
  const button = $("add");
  const label = button.lastChild.textContent;
  button.disabled = true;
  button.lastChild.textContent = "Создаю…";
  showError(null);
  try {
    const resp = await api(inboundPath(), { method: "POST", body: JSON.stringify({ user }) });
    const c = await resp.json();
    $("user").value = "";
    state.users = null; // a new panel user may have been created
    closeSuggest();
    await loadInbounds();
    await loadClients();
    await openQR(c);
  } finally {
    button.disabled = false;
    button.lastChild.textContent = label;
  }
}

async function main() {
  state.token = readToken();
  try {
    state.loginPath = (await (await fetch("api/meta")).json()).loginPath || state.loginPath;
  } catch { /* keep default */ }
  if (!state.token) {
    location.assign(state.loginPath);
    return;
  }
  $("refresh").addEventListener("click", () => loadClients().catch(showError));
  $("logout").addEventListener("click", () => location.assign(state.loginPath));
  $("add").addEventListener("click", () => addClient().catch(showError));
  $("user").addEventListener("focus", () => openSuggest().catch(showError));
  $("user").addEventListener("click", () => openSuggest().catch(showError));
  $("user").addEventListener("input", () => openSuggest().catch(showError));
  $("user").addEventListener("blur", closeSuggest);
  $("user").addEventListener("keydown", onUserKey);
  $("confirm-no").addEventListener("click", () => $("confirm").close());
  $("confirm-yes").addEventListener("click", async () => {
    $("confirm").close();
    try {
      await api(inboundPath() + "/" + encodeURIComponent(state.pendingDelete.email), { method: "DELETE" });
      await loadInbounds();
      await loadClients();
    } catch (e) { showError(e); }
  });
  $("qr-close").addEventListener("click", () => $("qr-dialog").close());
  $("qr-download").addEventListener("click", () => downloadConfig().catch(showError));
  await loadInbounds();
  await loadClients();
}

main().catch(showError);
