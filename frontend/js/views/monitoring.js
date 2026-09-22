import { api } from "../api.js";
import {
  emptyState, html, icon, isoTz, loading, logsLink, modal, navigate, pager, raw, setHTML, sevBadge, sevClass, toast,
  verdictBadge, debounce,
} from "../utils.js";

const TABS = [
  { key: "main", label: "Main Channel" },
  { key: "investigation", label: "Investigation Channel" },
  { key: "closed", label: "Closed Alerts" },
];
const SEVERITIES = ["Critical", "High", "Medium", "Low"];

export function mount(el) {
  const state = { tab: "main", page: 1, open: new Set(), filtersOpen: false, severity: new Set(), type: "", search: "",
    data: null, stats: null, loading: true };
  let alive = true;

  setHTML(el, html`
    <div class="sev-cards" id="sevCards"></div>
    <div class="channel-tabs" role="tablist"></div>
    <section class="panel monitor-panel">
      <div class="filter-slot"></div>
      <div class="table-wrap"><div class="table-slot"></div></div>
      <div class="pager-row pager-slot"></div>
    </section>`);
  const tabsEl = el.querySelector(".channel-tabs");
  const filterSlot = el.querySelector(".filter-slot");
  const tableSlot = el.querySelector(".table-slot");
  const pagerSlot = el.querySelector(".pager-slot");

  async function load() {
    state.loading = true;
    renderTable();
    try {
      const [data, stats] = await Promise.all([
        api.get("/alerts", { status: state.tab, page: state.page, page_size: 10,
          severity: [...state.severity].join(","), type: state.type, search: state.search }),
        api.get("/alerts/stats"),
      ]);
      if (!alive) return;
      Object.assign(state, { data, stats, loading: false });
      if (state.page > data.pages) { state.page = data.pages; return load(); }
    } catch (e) {
      state.loading = false;
      state.data = { error: e.message };
    }
    renderTabs(); renderFilters(); renderTable();
  }

  function renderSevCards() {
    const counts = state.stats?.by_severity?.[state.tab] || {};
    const total = SEVERITIES.reduce((n, s) => n + (counts[s] || 0), 0);
    setHTML(el.querySelector("#sevCards"), SEVERITIES.map((s) => {
      const n = counts[s] || 0;
      const on = state.severity.has(s);
      return html`<button class="sev-card sev-${s} ${on ? "on" : ""}" data-sev="${s}" aria-pressed="${on}"
          title="${on ? "Remove" : "Filter by"} ${s}">
        <span class="sev-card-top"><span class="sev-badge sev-${s}"><span class="dot"></span>${s}</span>
          <span class="sev-card-ic">${icon(s === "Critical" || s === "High" ? "alert" : "activity")}</span></span>
        <span class="sev-card-n">${n}</span>
        <span class="sev-card-bar"><i style="width:${total ? (n / total) * 100 : 0}%"></i></span>
      </button>`;
    }));
  }

  function renderTabs() {
    renderSevCards();
    setHTML(tabsEl, TABS.map((t) => html`<button role="tab" class="channel-tab ${state.tab === t.key ? "active" : ""}"
      aria-selected="${state.tab === t.key}" data-tab="${t.key}">${t.label}${state.stats
        ? html`<span class="count">${state.stats[t.key]}</span>` : ""}</button>`));
  }

  function renderFilters() {
    if (!state.filtersOpen) { filterSlot.innerHTML = ""; return; }
    setHTML(filterSlot, html`<div class="filter-bar">
      ${SEVERITIES.map((s) => html`<button class="chip-toggle ${sevClass(s)} ${state.severity.has(s) ? "on" : ""}" data-sev="${s}">${s}</button>`)}
      <select class="select" data-type aria-label="Alert type">
        <option value="">All types</option>
        ${(state.stats?.types || []).map((t) => html`<option ${raw(t === state.type ? "selected" : "")}>${t}</option>`)}
      </select>
      <div class="search-input" style="flex:1;min-width:220px">${icon("search")}
        <input class="input" data-search placeholder="Search rule name, event ID, hostname, IP…" value="${state.search}"></div>
      <button class="btn btn-ghost btn-sm" data-reset>Reset</button>
    </div>`);
  }

  function actionCell(a) {
    if (state.tab === "main") {
      return html`<button class="icon-btn" title="Take ownership" aria-label="Take ownership" data-act="take" data-id="${a.id}">${icon("userPlus")}</button>`;
    }
    if (state.tab === "investigation") {
      return html`
        <button class="icon-btn sm" title="Create case" aria-label="Create case" data-act="case" data-id="${a.id}">${icon("folderPlus")}</button>
        <button class="icon-btn sm" title="Close alert" aria-label="Close alert" data-act="close" data-id="${a.id}">${icon("checkCircle")}</button>
        <button class="icon-btn sm" title="Return to main channel" aria-label="Return to main channel" data-act="release" data-id="${a.id}">${icon("undo")}</button>`;
    }
    return verdictBadge(a.verdict);
  }

  function detailRow(a) {
    const d = a.details || {};
    const host = d.Hostname, ip = d["IP Address"] || d["Source IP"] || d["Destination IP"];
    const pivot = host ? `hostname="${host}"` : ip ? `source_address="${ip}" OR destination_address="${ip}"` : "";
    return html`<tr class="detail"><td colspan="7"><div class="alert-detail">
      <div class="kv">
        <div class="k">Event ID</div><div class="v">${a.event_id}</div>
        <div class="k">Event Time</div><div class="v">${isoTz(a.created_at)}</div>
        <div class="k">Rule</div><div class="v">${a.rule_name}</div>
        ${Object.entries(d).map(([k, v]) => html`<div class="k">${k}</div><div class="v mono">${v}</div>`)}
        ${a.owner ? html`<div class="k">Owner</div><div class="v">${a.owner}</div>` : ""}
        ${a.status === "closed" ? html`<div class="k">Verdict</div><div class="v">${verdictBadge(a.verdict)}</div>
          <div class="k">Closed At</div><div class="v">${isoTz(a.closed_at)}</div>
          <div class="k">Analyst Note</div><div class="v">${a.close_note || "-"}</div>` : ""}
      </div>
      <div class="actions">
        ${pivot ? html`<a class="btn btn-sm" href="${logsLink(pivot)}">${icon("list")} Search in Log Management</a>` : ""}
        ${host ? html`<a class="btn btn-sm" href="#/endpoints?host=${encodeURIComponent(host)}">${icon("hdd")} Endpoint ${host}</a>` : ""}
        ${a.status === "main" ? html`<button class="btn btn-sm btn-primary" data-act="take" data-id="${a.id}">${icon("userPlus")} Take Ownership</button>` : ""}
        ${a.status === "investigation" ? html`
          <button class="btn btn-sm" data-act="case" data-id="${a.id}">${icon("folderPlus")} Create Case</button>
          <button class="btn btn-sm btn-primary" data-act="close" data-id="${a.id}">${icon("checkCircle")} Close Alert</button>` : ""}
      </div>
    </div></td></tr>`;
  }

  function renderTable() {
    if (state.loading && !state.data) { setHTML(tableSlot, loading()); pagerSlot.innerHTML = ""; return; }
    const d = state.data;
    if (d?.error) { setHTML(tableSlot, html`<div class="error-box">${d.error}</div>`); return; }
    const closed = state.tab === "closed";
    setHTML(tableSlot, html`<table class="table">
      <thead><tr>
        <th class="chev"><button class="icon-btn sm filter-toggle" data-filters title="Filters" aria-label="Toggle filters">${icon("sliders")}</button></th>
        <th>Severity</th><th>Date</th><th>Rule Name</th><th>EventID</th><th>Type</th>
        <th class="action-cell">${closed ? "Verdict" : "Action"}</th>
      </tr></thead>
      <tbody>
        ${d.items.length ? d.items.map((a) => {
          const open = state.open.has(a.id);
          return html`<tr class="row sev-row sev-${a.severity} ${open ? "open" : ""}">
            <td class="chev"><button data-toggle="${a.id}" aria-expanded="${open}" aria-label="Details">${icon("chevDown")}</button></td>
            <td>${sevBadge(a.severity)}</td>
            <td class="nowrap">${isoTz(a.created_at)}</td>
            <td class="clickable" data-toggle="${a.id}">${a.rule_name}</td>
            <td>${a.event_id}</td>
            <td>${a.type}</td>
            <td class="action-cell">${actionCell(a)}</td>
          </tr>${open ? detailRow(a) : ""}`;
        }) : html`<tr><td colspan="7">${emptyState("No alerts in this channel")}</td></tr>`}
      </tbody></table>`);
    setHTML(pagerSlot, d.pages > 1 || d.items.length ? pager(state.page, d.pages) : "");
  }

  async function act(kind, id) {
    const a = state.data.items.find((x) => x.id === id);
    if (kind === "take") {
      modal({
        title: "Take Ownership",
        body: html`<p>Assign <b>${a.rule_name}</b> to yourself and move it to the Investigation Channel?</p>`,
        confirmText: "Take Ownership",
        onConfirm: async () => { await api.post(`/alerts/${id}/take`); toast(`EventID ${a.event_id} moved to Investigation Channel`); load(); },
      });
    } else if (kind === "release") {
      await api.post(`/alerts/${id}/release`);
      toast(`EventID ${a.event_id} returned to Main Channel`);
      load();
    } else if (kind === "close") {
      modal({
        title: `Close Alert · EventID ${a.event_id}`,
        body: html`<p class="muted" style="margin-top:0">${a.rule_name}</p>
          <div class="form-row"><span class="field-label">Verdict</span><div class="radio-cards">
            <label class="radio-card"><input type="radio" name="verdict" value="True Positive"><span><b>True Positive</b><span class="muted small">Malicious activity confirmed</span></span></label>
            <label class="radio-card"><input type="radio" name="verdict" value="False Positive"><span><b>False Positive</b><span class="muted small">Benign / expected behaviour</span></span></label>
          </div></div>
          <div class="form-row"><label class="field-label" for="closeNote">Analyst note</label>
            <textarea id="closeNote" class="input" rows="4" style="width:100%" placeholder="Summarise your findings, evidence and actions taken…"></textarea></div>`,
        confirmText: "Close Alert",
        onConfirm: async (body) => {
          const verdict = body.querySelector("input[name=verdict]:checked")?.value;
          if (!verdict) { toast("Select a verdict first", "error"); return false; }
          await api.post(`/alerts/${id}/close`, { verdict, note: body.querySelector("#closeNote").value });
          toast(`EventID ${a.event_id} closed as ${verdict}`);
          load();
        },
      });
    } else if (kind === "case") {
      modal({
        title: "Create Case",
        body: html`<div class="form-row"><label class="field-label" for="cTitle">Title</label>
            <input id="cTitle" class="input" style="width:100%" value="${a.rule_name}"></div>
          <div class="form-row"><label class="field-label" for="cDesc">Description</label>
            <textarea id="cDesc" class="input" rows="4" style="width:100%">${Object.entries(a.details || {}).map(([k, v]) => `${k}: ${v}`).join("\n")}</textarea></div>`,
        confirmText: "Create Case",
        onConfirm: async (body) => {
          try {
            const c = await api.post("/cases", { alert_id: id, title: body.querySelector("#cTitle").value,
              severity: a.severity, description: body.querySelector("#cDesc").value });
            toast(`Case #${c.id} created`);
            navigate("/cases", { id: c.id });
          } catch (e) {
            if (e.status === 409 && e.detail?.case_id) { navigate("/cases", { id: e.detail.case_id }); return; }
            throw e;
          }
        },
      });
    }
  }

  const onSearch = debounce(() => { state.page = 1; load(); }, 300);

  el.addEventListener("click", (e) => {
    const t = e.target.closest("[data-tab],[data-toggle],[data-page],[data-act],[data-filters],[data-sev],[data-reset]");
    if (!t) return;
    if (t.dataset.tab) {
      if (t.dataset.tab === state.tab) return;
      Object.assign(state, { tab: t.dataset.tab, page: 1, data: null });
      state.open.clear(); renderTabs(); load();
    } else if (t.dataset.toggle) {
      const id = Number(t.dataset.toggle);
      state.open.has(id) ? state.open.delete(id) : state.open.add(id);
      renderTable();
    } else if (t.dataset.page) {
      if (t.disabled) return;
      state.page = Number(t.dataset.page); load();
    } else if (t.dataset.act) {
      act(t.dataset.act, Number(t.dataset.id)).catch((err) => toast(err.message, "error"));
    } else if (t.hasAttribute("data-filters")) {
      state.filtersOpen = !state.filtersOpen; renderFilters();
    } else if (t.dataset.sev) {
      state.severity.has(t.dataset.sev) ? state.severity.delete(t.dataset.sev) : state.severity.add(t.dataset.sev);
      state.page = 1; renderFilters(); renderSevCards(); load();
    } else if (t.hasAttribute("data-reset")) {
      Object.assign(state, { severity: new Set(), type: "", search: "", page: 1 });
      renderFilters(); load();
    }
  });
  el.addEventListener("change", (e) => {
    if (e.target.matches("[data-type]")) { state.type = e.target.value; state.page = 1; load(); }
  });
  el.addEventListener("input", (e) => {
    if (e.target.matches("[data-search]")) { state.search = e.target.value; onSearch(); }
  });

  renderTabs();
  load();
  return () => { alive = false; };
}
