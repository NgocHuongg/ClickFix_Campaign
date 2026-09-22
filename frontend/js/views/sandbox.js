import { api } from "../api.js";
import { debounce, emptyState, html, icon, isoTz, loading, logsLink, raw, setHTML } from "../utils.js";

const VERDICT = { Malicious: ["red", "var(--critical)"], Suspicious: ["orange", "var(--high)"], Clean: ["green", "var(--ok)"] };

function gauge(score, color) {
  const r = 42, c = 2 * Math.PI * r;
  return raw(`<div class="score"><svg viewBox="0 0 100 100"><circle cx="50" cy="50" r="${r}" fill="none" stroke="#1f2a44" stroke-width="9"/>
    <circle cx="50" cy="50" r="${r}" fill="none" stroke="${color}" stroke-width="9" stroke-linecap="round"
      stroke-dasharray="${(c * score) / 100} ${c}"/></svg><div class="n">${Number(score)}</div></div>`);
}

export function mount(el, params) {
  const state = { items: [], selected: null, search: params.search || "" };
  setHTML(el, html`
    <div class="page-head"><div><h1 class="page-title">Sandbox</h1>
      <p class="page-sub">Dynamic analysis reports: behaviour, network indicators and MITRE ATT&amp;CK mapping.</p></div></div>
    <div class="split">
      <section class="panel">
        <div class="list-tools"><div class="search-input">${icon("search")}<input class="input" data-search placeholder="File name, MD5 or SHA256…" value="${state.search}"></div></div>
        <div class="list" id="sbList">${loading()}</div>
      </section>
      <section class="panel detail" id="sbDetail"></section>
    </div>`);
  const listEl = el.querySelector("#sbList"), detailEl = el.querySelector("#sbDetail");

  async function load() {
    try { state.items = await api.get("/sandbox", { search: state.search }); }
    catch (e) { setHTML(listEl, html`<div class="error-box">${e.message}</div>`); return; }
    if (!state.items.some((r) => r.id === state.selected)) state.selected = state.items[0]?.id ?? null;
    render();
  }

  function render() {
    setHTML(listEl, state.items.length ? state.items.map((r) => html`
      <div class="list-item ${r.id === state.selected ? "sel" : ""}" data-id="${r.id}" tabindex="0">
        <div class="row1"><span class="title">${r.file_name}</span><span class="badge ${VERDICT[r.verdict][0]}">${r.verdict}</span></div>
        <div class="meta"><span>${r.file_type}</span><span>Score ${r.score}/100</span><span>${r.submitted_at.slice(0, 10)}</span></div>
      </div>`) : emptyState("No reports match", "box"));
    const r = state.items.find((x) => x.id === state.selected);
    if (!r) { setHTML(detailEl, emptyState("Select a report", "box")); return; }
    const rep = r.report || {};
    setHTML(detailEl, html`
      <div class="detail-head" style="align-items:center">
        <div style="display:flex;gap:18px;align-items:center">${gauge(r.score, VERDICT[r.verdict][1])}
          <div><h2>${r.file_name}</h2><span class="badge ${VERDICT[r.verdict][0]}">${r.verdict}</span>
            <div class="muted small" style="margin-top:6px">${r.file_type} · analysed ${isoTz(r.submitted_at)}</div></div></div>
        <a class="btn btn-sm" href="${logsLink(`raw_log CONTAINS "${r.md5}" OR raw_log CONTAINS "${r.file_name}"`)}">${icon("list")} Hunt in logs</a>
      </div>
      <div class="kv"><div class="k">SHA256</div><div class="v mono">${r.sha256}</div><div class="k">MD5</div><div class="v mono">${r.md5}</div></div>
      <h3>Signatures</h3>
      ${rep.signatures?.length ? html`<ul class="list-plain">${rep.signatures.map((s) => html`<li>${s}</li>`)}</ul>` : html`<p class="muted">No malicious signatures</p>`}
      <h3>MITRE ATT&amp;CK</h3>
      ${rep.mitre?.length ? rep.mitre.map((m) => html`<span class="badge purple" style="margin:0 6px 6px 0">${m}</span>`) : html`<p class="muted">None</p>`}
      <h3>Processes</h3>
      ${rep.processes?.length ? html`<div class="raw-block">${rep.processes.map((p, i) => `${"  ".repeat(i)}${i ? "└─ " : ""}${p}\n`)}</div>` : html`<p class="muted">None</p>`}
      <h3>Network</h3>
      ${rep.network?.length ? html`<ul class="list-plain mono">${rep.network.map((n) => html`<li>${n}</li>`)}</ul>` : html`<p class="muted">No network activity</p>`}`);
  }

  el.addEventListener("click", (e) => {
    const item = e.target.closest(".list-item");
    if (item) { state.selected = Number(item.dataset.id); render(); }
  });
  el.addEventListener("keydown", (e) => { if (e.key === "Enter" && e.target.matches(".list-item")) e.target.click(); });
  const onSearch = debounce(load, 300);
  el.addEventListener("input", (e) => { if (e.target.matches("[data-search]")) { state.search = e.target.value; onSearch(); } });
  load();
}
