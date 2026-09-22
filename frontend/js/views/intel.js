import { api } from "../api.js";
import { debounce, emptyState, html, icon, loading, logsLink, setHTML } from "../utils.js";

const TYPES = ["ip", "domain", "url", "md5", "sha256"];

export function mount(el) {
  const state = { search: "", type: "" };
  setHTML(el, html`
    <div class="page-head"><div><h1 class="page-title">Threat Intel</h1>
      <p class="page-sub">Look up IPs, domains, URLs and file hashes against intelligence feeds, then pivot into your own telemetry.</p></div></div>
    <section class="panel">
      <div class="list-tools">
        <div class="search-input">${icon("search")}<input class="input" data-search placeholder="Search IOC value, tag, threat or source…" aria-label="Search IOCs"></div>
        <select class="select" data-type aria-label="IOC type"><option value="">All types</option>${TYPES.map((t) => html`<option value="${t}">${t.toUpperCase()}</option>`)}</select>
      </div>
      <div class="table-wrap" id="iocTable">${loading()}</div>
    </section>`);
  const box = el.querySelector("#iocTable");

  async function load() {
    let items;
    try { items = await api.get("/intel", { search: state.search, ioc_type: state.type }); }
    catch (e) { setHTML(box, html`<div class="error-box">${e.message}</div>`); return; }
    setHTML(box, items.length ? html`<table class="table compact lined">
      <thead><tr><th>Type</th><th>Value</th><th>Threat</th><th>Tags</th><th>Source</th><th>Confidence</th><th>First seen</th><th>Seen in logs</th></tr></thead>
      <tbody>${items.map((i) => {
        const c = i.confidence >= 80 ? "var(--critical)" : i.confidence >= 60 ? "var(--high)" : "var(--medium)";
        return html`<tr class="row">
          <td><span class="badge purple">${i.ioc_type.toUpperCase()}</span></td>
          <td class="mono" style="max-width:340px;overflow-wrap:anywhere">${i.value}</td>
          <td>${i.threat}</td>
          <td>${(i.tags || "").split(",").filter(Boolean).map((t) => html`<span class="tag">${t}</span>`)}</td>
          <td>${i.source}</td>
          <td><span class="conf"><i style="width:${i.confidence}%;background:${c}"></i></span> <span class="small muted">${i.confidence}</span></td>
          <td class="mono">${i.first_seen.slice(0, 10)}</td>
          <td>${i.log_hits ? html`<a href="${logsLink(`raw_log CONTAINS "${i.value}"`)}">${i.log_hits} events →</a>` : html`<span class="muted">0</span>`}</td>
        </tr>`;
      })}</tbody></table>` : emptyState("No indicators match", "shield"));
  }
  const onSearch = debounce(load, 300);
  el.addEventListener("input", (e) => { if (e.target.matches("[data-search]")) { state.search = e.target.value; onSearch(); } });
  el.addEventListener("change", (e) => { if (e.target.matches("[data-type]")) { state.type = e.target.value; load(); } });
  load();
}
