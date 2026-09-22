import { api } from "../api.js";
import { debounce, emptyState, html, icon, isoTz, loading, logsLink, modal, setHTML, sevBadge, toast } from "../utils.js";

const TABS = [
  ["processes", "Processes"], ["network", "Network Action"], ["terminal", "Terminal History"],
  ["browser", "Browser History"], ["alerts", "Alerts"],
];

export function mount(el, params) {
  const state = { items: [], selected: null, host: params.host || null, search: "", detail: null, tab: "processes" };

  setHTML(el, html`
    <div class="page-head"><div><h1 class="page-title">Endpoint Security</h1>
      <p class="page-sub">EDR view of managed hosts: process tree, network activity, command history and containment.</p></div></div>
    <div class="split">
      <section class="panel">
        <div class="list-tools"><div class="search-input">${icon("search")}<input class="input" data-search placeholder="Hostname, IP or user…"></div></div>
        <div class="list" id="epList">${loading()}</div>
      </section>
      <section class="panel detail" id="epDetail"></section>
    </div>`);
  const listEl = el.querySelector("#epList"), detailEl = el.querySelector("#epDetail");

  async function loadList() {
    try { state.items = await api.get("/endpoints", { search: state.search }); }
    catch (e) { setHTML(listEl, html`<div class="error-box">${e.message}</div>`); return; }
    if (state.host) {
      state.selected = state.items.find((i) => i.hostname === state.host)?.id ?? null;
      state.host = null;
    }
    if (!state.selected && state.items.length) state.selected = state.items[0].id;
    renderList(); loadDetail();
  }

  function renderList() {
    setHTML(listEl, state.items.length ? state.items.map((e) => html`
      <div class="list-item ${e.id === state.selected ? "sel" : ""}" data-id="${e.id}" tabindex="0">
        <div class="row1"><span class="title">${e.hostname}</span>
          ${e.contained ? html`<span class="badge red">${icon("lock")} Contained</span>` : html`<span class="badge green">Online</span>`}</div>
        <div class="meta"><span class="mono">${e.ip_address}</span><span>${e.os}</span>
          ${e.open_alerts ? html`<span class="sev sev-High">${e.open_alerts} open alert${e.open_alerts > 1 ? "s" : ""}</span>` : ""}</div>
      </div>`) : emptyState("No endpoints found", "hdd"));
  }

  async function loadDetail() {
    if (!state.selected) { setHTML(detailEl, emptyState("Select an endpoint", "hdd")); return; }
    setHTML(detailEl, loading());
    try { state.detail = await api.get(`/endpoints/${state.selected}`); }
    catch (e) { setHTML(detailEl, html`<div class="error-box">${e.message}</div>`); return; }
    renderDetail();
  }

  function tabBody(d) {
    if (state.tab === "processes") {
      return d.processes.length ? html`<div class="table-wrap"><table class="table compact lined"><thead><tr><th>Time</th><th>Process</th><th>Command line</th></tr></thead>
        <tbody>${d.processes.map((p) => html`<tr class="row"><td class="mono" style="white-space:nowrap">${p.timestamp}</td><td class="mono">${p.process}</td><td class="mono">${p.command_line || ""}</td></tr>`)}</tbody></table></div>`
        : emptyState("No process telemetry");
    }
    if (state.tab === "network") {
      return d.network.length ? html`<div class="table-wrap"><table class="table compact lined"><thead><tr><th>Time</th><th>Type</th><th>Destination</th><th>Process</th><th>Action</th></tr></thead>
        <tbody>${d.network.map((n) => html`<tr class="row"><td class="mono" style="white-space:nowrap">${n.timestamp}</td><td>${n.type}</td>
          <td class="mono"><a href="${logsLink(`destination_address="${n.destination_address}"`)}">${n.destination_address}</a>${n.destination_port ? ":" + n.destination_port : ""}</td>
          <td class="mono">${n.process || "-"}</td><td>${n.action}</td></tr>`)}</tbody></table></div>`
        : emptyState("No network telemetry");
    }
    if (state.tab === "terminal") {
      return d.terminal_history.length ? html`<div class="raw-block">${d.terminal_history.map((t) => `[${t.timestamp}] ${t.username || ""}> ${t.command_line}\n`)}</div>`
        : emptyState("No shell commands recorded", "terminal");
    }
    if (state.tab === "browser") {
      return d.browser_history.length ? html`<table class="table compact lined"><thead><tr><th>Time</th><th>URL</th></tr></thead>
        <tbody>${d.browser_history.map((b) => html`<tr class="row"><td class="mono">${b.time}</td><td class="mono">${b.url}</td></tr>`)}</tbody></table>`
        : emptyState("No browser history");
    }
    return d.alerts.length ? html`<table class="table compact lined"><thead><tr><th>Severity</th><th>Rule</th><th>Status</th><th>Date</th></tr></thead>
      <tbody>${d.alerts.map((a) => html`<tr class="row"><td>${sevBadge(a.severity)}</td><td>${a.rule_name}</td><td>${a.status}</td><td class="mono">${isoTz(a.created_at)}</td></tr>`)}</tbody></table>`
      : emptyState("No alerts for this host", "checkCircle");
  }

  function renderDetail() {
    const d = state.detail;
    setHTML(detailEl, html`
      <div class="detail-head"><div><h2>${d.hostname}</h2>
        <div class="muted small">${d.os} · Last seen ${d.last_seen ? isoTz(d.last_seen) : "-"}</div></div>
        <div class="btn-row">
          <a class="btn btn-sm" href="${logsLink(`hostname="${d.hostname}"`)}">${icon("list")} Logs</a>
          <button class="btn btn-sm ${d.contained ? "" : "btn-danger"}" data-contain>${icon(d.contained ? "unlock" : "lock")} ${d.contained ? "Release Containment" : "Contain Host"}</button>
        </div></div>
      <div class="kv">
        <div class="k">IP Address</div><div class="v mono">${d.ip_address}</div>
        <div class="k">Primary User</div><div class="v">${d.domain && d.domain !== "-" ? `${d.domain}\\${d.primary_user}` : d.primary_user}</div>
        <div class="k">Status</div><div class="v">${d.contained ? html`<span class="badge red">Contained - network isolated</span>` : html`<span class="badge green">Online</span>`}</div>
      </div>
      <div class="subtabs" role="tablist">${TABS.map(([k, l]) => html`<button role="tab" class="${state.tab === k ? "active" : ""}" data-tab="${k}">${l}</button>`)}</div>
      <div style="padding-top:12px">${tabBody(d)}</div>`);
  }

  el.addEventListener("click", (e) => {
    const item = e.target.closest(".list-item");
    if (item) { state.selected = Number(item.dataset.id); renderList(); loadDetail(); return; }
    const tab = e.target.closest("[data-tab]");
    if (tab) { state.tab = tab.dataset.tab; renderDetail(); return; }
    if (e.target.closest("[data-contain]")) {
      const d = state.detail, contain = !d.contained;
      modal({
        title: contain ? "Contain host?" : "Release containment?",
        body: html`<p>${contain ? "Network-isolate" : "Restore network access for"} <b>${d.hostname}</b> (${d.ip_address}).</p>`,
        confirmText: contain ? "Contain" : "Release", danger: contain,
        onConfirm: async () => {
          state.detail = { ...state.detail, ...(await api.post(`/endpoints/${d.id}/containment`, { contained: contain })) };
          toast(`${d.hostname} ${contain ? "contained" : "released"}`);
          renderDetail();
          state.items = await api.get("/endpoints", { search: state.search }); renderList();
        },
      });
    }
  });
  el.addEventListener("keydown", (e) => { if (e.key === "Enter" && e.target.matches(".list-item")) e.target.click(); });
  const onSearch = debounce(() => { state.selected = null; loadList(); }, 300);
  el.addEventListener("input", (e) => { if (e.target.matches("[data-search]")) { state.search = e.target.value; onSearch(); } });

  loadList();
}
