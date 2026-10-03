"use strict";

const state = { token: "", inbound: null, loginPath: "/auth/login", pendingDelete: null, qrEmail: null };
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
  $("qr-img").src = URL.createObjectURL(svg);
  $("qr-dialog").showModal();
}

async function downloadConfig() {
  const resp = await api(inboundPath() + "/" + encodeURIComponent(state.qrEmail) + "/config");
  const url = URL.createObjectURL(await resp.blob());
  const a = document.createElement("a");
  a.href = url;
  a.download = "wg-" + state.qrEmail + ".conf";
  a.click();
  URL.revokeObjectURL(url);
}

function askDelete(c) {
  state.pendingDelete = c;
  $("confirm-text").textContent = (c.username || c.email) + " (" + c.address + ")";
  $("confirm").showModal();
}

async function addClient() {
  const user = $("user").value.trim();
  if (!user) return;
  const resp = await api(inboundPath(), { method: "POST", body: JSON.stringify({ user }) });
  const c = await resp.json();
  $("user").value = "";
  await loadInbounds();
  await loadClients();
  await openQR(c);
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
