import { api } from "../api.js";
import { debounce, emptyState, html, icon, isoTz, loading, modal, navigate, raw, setHTML, sevBadge, toast, verdictBadge } from "../utils.js";

const STATUS_BADGE = { Open: "blue", "In Progress": "orange", Closed: "green" };

export function update(params) {
  return instance ? (instance.select(params.id ? Number(params.id) : null), true) : false;
}
let instance = null;

export function mount(el, params) {
  const state = { items: [], selected: params.id ? Number(params.id) : null, status: "", search: "", detail: null };

  setHTML(el, html`
    <div class="page-head"><div><h1 class="page-title">Case Management</h1>
      <p class="page-sub">Track investigations opened from alerts, document findings and record verdicts.</p></div>
      <button class="btn btn-primary" data-new>${icon("plus")} New Case</button></div>
    <div class="split">
      <section class="panel">
        <div class="list-tools">
          <div class="search-input">${icon("search")}<input class="input" data-search placeholder="Search cases…"></div>
          <select class="select" data-status aria-label="Status"><option value="">All</option><option>Open</option><option>In Progress</option><option>Closed</option></select>
        </div>
        <div class="list" id="caseList">${loading()}</div>
      </section>
      <section class="panel detail" id="caseDetail"></section>
    </div>`);
  const listEl = el.querySelector("#caseList");
  const detailEl = el.querySelector("#caseDetail");

  async function loadList() {
    try {
      state.items = await api.get("/cases", { status: state.status, search: state.search });
    } catch (e) { setHTML(listEl, html`<div class="error-box">${e.message}</div>`); return; }
    if (!state.selected && state.items.length) state.selected = state.items[0].id;
    renderList();
    loadDetail();
  }

  function renderList() {
    setHTML(listEl, state.items.length ? state.items.map((c) => html`
      <div class="list-item ${c.id === state.selected ? "sel" : ""}" data-id="${c.id}" tabindex="0">
        <div class="row1"><span class="title">#${c.id} · ${c.title}</span><span class="badge ${STATUS_BADGE[c.status]}">${c.status}</span></div>
        <div class="meta">${sevBadge(c.severity)}
          ${c.alert_event_id ? html`<span>EventID ${c.alert_event_id}</span>` : ""}
          <span>${c.note_count} notes</span><span>Updated ${isoTz(c.updated_at).slice(0, 16).replace("T", " ")}</span></div>
      </div>`) : emptyState("No cases yet. Create one from an alert in the Investigation Channel.", "clipboard"));
  }

  async function loadDetail() {
    if (!state.selected) { setHTML(detailEl, emptyState("Select a case", "clipboard")); return; }
    setHTML(detailEl, loading());
    try { state.detail = await api.get(`/cases/${state.selected}`); }
    catch (e) { setHTML(detailEl, html`<div class="error-box">${e.message}</div>`); return; }
    renderDetail();
  }

  function renderDetail() {
    const c = state.detail;
    setHTML(detailEl, html`
      <div class="detail-head"><div>
        <h2>#${c.id} · ${c.title}</h2>
        <div class="meta muted small">Created ${isoTz(c.created_at)} · Assignee ${c.assignee || "-"}</div></div>
        ${c.alert_id ? html`<a class="btn btn-sm" href="#/monitoring">${icon("monitor")} EventID ${c.alert_event_id}</a>` : ""}
      </div>
      <div class="stat-row">
        <div class="panel stat"><div class="l">Severity</div><div style="margin-top:10px">${sevBadge(c.severity)}</div></div>
        <div class="panel stat"><div class="l">Status</div>
          <select class="select" data-field="status" style="margin-top:6px;width:100%">
            ${["Open", "In Progress", "Closed"].map((s) => html`<option ${raw(s === c.status ? "selected" : "")}>${s}</option>`)}</select></div>
        <div class="panel stat"><div class="l">Verdict</div>
          <select class="select" data-field="verdict" style="margin-top:6px;width:100%">
            <option value="" ${raw(c.verdict ? "" : "selected")} disabled>Undetermined</option>
            ${["True Positive", "False Positive"].map((s) => html`<option ${raw(s === c.verdict ? "selected" : "")}>${s}</option>`)}</select></div>
      </div>
      ${c.alert_rule ? html`<div class="kv" style="margin-bottom:10px"><div class="k">Linked alert</div><div class="v">${c.alert_rule}</div></div>` : ""}
      <h3>Description</h3>
      <div class="email-body">${c.description || "—"}</div>
      <h3>Investigation notes</h3>
      <ul class="timeline">${c.notes.map((n) => html`<li><div class="when">${isoTz(n.created_at)} · ${n.author}</div><div class="body">${n.body}</div></li>`)}</ul>
      <div class="form-row" style="margin-top:8px">
        <textarea class="input" id="noteBody" rows="3" style="width:100%" placeholder="Add a note: evidence, IOCs, containment actions…"></textarea></div>
      <div class="btn-row"><button class="btn btn-primary" data-add-note>${icon("plus")} Add Note</button>
        ${c.verdict ? verdictBadge(c.verdict) : ""}</div>`);
  }

  async function select(id) {
    if (id === state.selected && state.detail) return;
    state.selected = id;
    renderList();
    loadDetail();
  }

  el.addEventListener("click", async (e) => {
    const item = e.target.closest(".list-item");
    if (item) { navigate("/cases", { id: item.dataset.id }); return; }
    if (e.target.closest("[data-add-note]")) {
      const ta = el.querySelector("#noteBody");
      if (!ta.value.trim()) return;
      try {
        state.detail = await api.post(`/cases/${state.selected}/notes`, { body: ta.value });
        renderDetail(); loadListQuiet();
      } catch (err) { toast(err.message, "error"); }
    }
    if (e.target.closest("[data-new]")) {
      modal({
        title: "New Case",
        body: html`<div class="form-row"><label class="field-label" for="nTitle">Title</label><input id="nTitle" class="input" style="width:100%"></div>
          <div class="form-row"><label class="field-label" for="nSev">Severity</label><select id="nSev" class="select" style="width:100%">
            <option>Low</option><option selected>Medium</option><option>High</option><option>Critical</option></select></div>
          <div class="form-row"><label class="field-label" for="nDesc">Description</label><textarea id="nDesc" class="input" rows="4" style="width:100%"></textarea></div>`,
        confirmText: "Create",
        onConfirm: async (b) => {
          const title = b.querySelector("#nTitle").value.trim();
          if (title.length < 3) { toast("Title must be at least 3 characters", "error"); return false; }
          const c = await api.post("/cases", { title, severity: b.querySelector("#nSev").value, description: b.querySelector("#nDesc").value });
          toast(`Case #${c.id} created`);
          state.selected = c.id; loadList();
        },
      });
    }
  });
  el.addEventListener("keydown", (e) => { if (e.key === "Enter" && e.target.matches(".list-item")) e.target.click(); });
  el.addEventListener("change", async (e) => {
    if (e.target.matches("[data-status]")) { state.status = e.target.value; state.selected = null; loadList(); }
    const f = e.target.dataset.field;
    if (f) {
      try {
        state.detail = await api.patch(`/cases/${state.selected}`, { [f]: e.target.value });
        toast(`Case ${f} updated`); renderDetail(); loadListQuiet();
      } catch (err) { toast(err.message, "error"); }
    }
  });
  const onSearch = debounce(() => { state.selected = null; loadList(); }, 300);
  el.addEventListener("input", (e) => { if (e.target.matches("[data-search]")) { state.search = e.target.value; onSearch(); } });

  async function loadListQuiet() {
    state.items = await api.get("/cases", { status: state.status, search: state.search });
    renderList();
  }

  instance = { select };
  loadList();
  return () => { instance = null; };
}
