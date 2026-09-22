import { api } from "../api.js";
import { debounce, emptyState, esc, highlight, html, icon, loading, modal, pager, raw, setHTML, toast } from "../utils.js";

/* ------------------------------------------------------------------ constants */
const TIME_PRESETS = [
  { key: "all", label: "All Time" },
  { key: "15m", label: "Last 15 minutes", sec: 900 },
  { key: "1h", label: "Last 1 hour", sec: 3600 },
  { key: "24h", label: "Last 24 hours", sec: 86400 },
  { key: "7d", label: "Last 7 days", sec: 7 * 86400 },
  { key: "30d", label: "Last 30 days", sec: 30 * 86400 },
  { key: "1y", label: "Last 1 year", sec: 365 * 86400 },
];
const KEYWORDS = ["AND", "OR", "NOT", "IN", "CONTAINS", "STARTSWITH", "ENDSWITH", "EXISTS"];
const COMMANDS = ["sort", "head", "limit"];
const FIELD_ALIASES = ["src", "dst", "sport", "dport", "host", "user", "image", "cmd", "raw", "time"];
const EXAMPLES = [
  ['source_address="172.16.20.69" AND type=OS', "Field equality, AND"],
  ['process=*powershell* NOT destination_address=172.16.20.69', "Wildcard, implicit AND, NOT"],
  ["destination_port IN (80, 443, 8080)", "Match any value in a list"],
  ['raw_log CONTAINS "WerFaultSecure" OR raw_log CONTAINS "EDR-Freeze"', "Substring match"],
  ["type=Authentication action=Failure | sort timestamp asc", "Pipe: sort ascending"],
  ['timestamp >= "2025-09-26 17:00" AND timestamp < "2025-09-26 18:00"', "Time comparison"],
  ["(type=Web OR type=Firewall) AND source_address STARTSWITH 198.51.100", "Grouping with parentheses"],
  ["powershell | head 20", "Free-text search + limit"],
];

/* platform "now" in UTC+03:00, formatted like DB timestamps */
const platformNow = (offsetSec = 0) =>
  new Date(Date.now() + 3 * 3600e3 - offsetSec * 1000).toISOString().slice(0, 19).replace("T", " ");
const quote = (v) => `"${String(v).replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;

/* ------------------------------------------------------------------ query <-> chips */
function chipToQuery(c) {
  if (c.op === "contains") return `${c.field} CONTAINS ${quote(c.value)}`;
  if (c.op === "!contains") return `NOT ${c.field} CONTAINS ${quote(c.value)}`;
  return `${c.field}${c.op}${quote(c.value)}`;
}
const chipsToQuery = (chips) => chips.map(chipToQuery).join(" AND ");

function queryToChips(q) {
  const text = q.trim();
  if (!text) return [];
  const parts = text.split(/\s+AND\s+/i);
  const chips = [];
  for (const p of parts) {
    let m = p.match(/^(NOT\s+)?(\w+)\s+CONTAINS\s+"((?:[^"\\]|\\.)*)"$/i);
    if (m) { chips.push({ field: m[2], op: m[1] ? "!contains" : "contains", value: m[3].replace(/\\(.)/g, "$1") }); continue; }
    m = p.match(/^(\w+)\s*(!=|=)\s*(?:"((?:[^"\\]|\\.)*)"|([^\s"()|]+))$/);
    if (m) { chips.push({ field: m[1], op: m[2], value: (m[3] ?? m[4]).replace(/\\(.)/g, "$1") }); continue; }
    return null;
  }
  return chips;
}

/* ------------------------------------------------------------------ client-side highlighter */
function highlightQuery(text, fields, errPos) {
  const fieldSet = new Set([...fields, ...FIELD_ALIASES]);
  const re = /("(?:[^"\\]|\\.)*"?|'(?:[^'\\]|\\.)*'?)|(!=|>=|<=|=|<|>|!)|(\|)|([(),])|(\s+)|([^\s()"',|=<>!]+)/g;
  let out = "", m, afterPipe = false;
  while ((m = re.exec(text))) {
    const [tok, str, op, pipe, punct, ws, word] = m;
    const start = m.index;
    let cls = "";
    if (str) cls = "tk-str";
    else if (op) cls = "tk-op";
    else if (pipe) { cls = "tk-pipe"; afterPipe = true; }
    else if (word) {
      const up = word.toUpperCase();
      if (afterPipe && COMMANDS.includes(word.toLowerCase())) { cls = "tk-cmd"; afterPipe = false; }
      else if (KEYWORDS.includes(up)) cls = "tk-kw";
      else if (/^-?\d+$/.test(word)) cls = "tk-num";
      else if (fieldSet.has(word.toLowerCase().replace(/^-/, ""))) {
        const rest = text.slice(start + word.length);
        if (/^\s*(!=|>=|<=|=|<|>)|^\s+(IN|NOT\s+IN|CONTAINS|STARTSWITH|ENDSWITH|EXISTS|asc|desc)\b|^\s*$|^\s*\|/i.test(rest)) cls = "tk-field";
      }
    }
    if (errPos != null && errPos >= start && errPos < start + tok.length && !ws) cls += " tk-err";
    out += cls ? `<span class="${cls}">${esc(tok)}</span>` : esc(tok);
  }
  if (errPos != null && errPos >= text.length) out += '<span class="tk-err">&nbsp;&nbsp;</span>';
  return out + "\n";
}

/* ------------------------------------------------------------------ view */
let instance = null;

export function update(params) {
  if (!instance) return false;
  instance.applyParams(params);
  return true;
}

export function mount(el, params) {
  const state = {
    mode: "basic", chips: [], pro: "", time: { preset: "all", from: "", to: "" },
    page: 1, pageSize: 20, sortAsc: false, fieldsHidden: false,
    fields: [], result: null, hist: null, loading: false, error: null, open: new Set(),
  };
  try { if (localStorage.getItem("soc.logs.mode") === "pro") state.mode = "pro"; } catch { }
  let ctrl = null;
  let popover = null;
  let suggest = { items: [], index: 0, open: false };

  setHTML(el, html`<section class="panel logs-panel">
    <div class="mode-toggle" role="group" aria-label="Search mode">
      <button data-mode="basic">Basic</button><button data-mode="pro">Pro</button>
    </div>
    <h1 class="logs-title">New Search</h1>
    <div class="searchbar">
      <div class="q-area" id="qArea"></div>
      <div class="time-picker">
        <button class="time-btn" id="timeBtn" aria-haspopup="true"></button>
        <div class="dropdown hidden" id="timeMenu"></div>
      </div>
      <button class="search-btn" id="searchBtn" title="Search" aria-label="Search">${icon("search")}</button>
    </div>
    <div class="query-error" id="qError"></div>
    <div id="meta"></div>
    <div id="hist"></div>
    <div class="toolbar">
      <div style="position:relative">
        <button class="filters-btn" id="filtersBtn">${icon("filter")} Filters</button>
        <div class="dropdown filters-menu hidden" id="filtersMenu"></div>
      </div>
      <div id="pagerTop"></div>
    </div>
    <div class="logs-body" id="logsBody">
      <aside class="fields-side" id="fieldsSide"></aside>
      <div class="events">
        <div class="events-head">
          <span title="Click an event to expand it. Hover a field value to include (+) or exclude (−) it.">${icon("info")}</span>
          <span class="sep"></span><span>Event</span><span class="badge green" id="countBadge">0</span>
        </div>
        <div class="events-list" id="events"></div>
      </div>
    </div>
  </section>`);

  const $ = (id) => el.querySelector("#" + id);

  /* ---------- effective query ---------- */
  function effectiveQuery() {
    let q = state.mode === "basic" ? chipsToQuery(state.chips) : state.pro.trim();
    if (state.sortAsc && !/\|\s*sort\b/i.test(q)) q = (q ? q + " " : "") + "| sort timestamp asc";
    return q;
  }
  function timeParams() {
    const t = state.time;
    if (t.preset === "custom") return { from: t.from, to: t.to };
    const p = TIME_PRESETS.find((x) => x.key === t.preset);
    return p?.sec ? { from: platformNow(p.sec), to: platformNow() } : {};
  }
  function syncUrl() {
    const qs = new URLSearchParams({ mode: state.mode });
    const q = state.mode === "basic" ? chipsToQuery(state.chips) : state.pro;
    if (q) qs.set("q", q);
    history.replaceState(null, "", "#/logs?" + qs);
  }

  /* ---------- search ---------- */
  async function search({ resetPage = false } = {}) {
    if (resetPage) state.page = 1;
    ctrl?.abort();
    ctrl = new AbortController();
    const signal = ctrl.signal;
    const q = effectiveQuery();
    const tp = timeParams();
    state.loading = true; state.error = null;
    renderError(); renderEvents(); syncUrl();
    try {
      const [result, hist] = await Promise.all([
        api.get("/logs/search", { q, ...tp, page: state.page, page_size: state.pageSize }, signal),
        api.get("/logs/histogram", { q, ...tp }, signal),
      ]);
      Object.assign(state, { result, hist, loading: false });
      state.open.clear();
      $("events").scrollTop = 0;
    } catch (e) {
      if (e.name === "AbortError") return;
      state.loading = false;
      state.error = e.detail && typeof e.detail === "object" ? e.detail : { message: e.message };
    }
    renderError(); renderMeta(); renderHist(); renderEvents(); renderPager();
    if (state.mode === "pro") renderEditorHighlight();
  }

  /* ---------- renderers ---------- */
  function renderMode() {
    el.querySelectorAll("[data-mode]").forEach((b) => b.classList.toggle("active", b.dataset.mode === state.mode));
    renderQueryArea();
  }

  function renderQueryArea() {
    const area = $("qArea");
    if (state.mode === "basic") {
      area.style.padding = "";
      setHTML(area, html`
        ${state.chips.map((c, i) => html`<span class="filter-chip" title="${chipToQuery(c)}">
          <span class="f">${c.field}</span>
          <span class="op" data-chip-op="${i}" title="Toggle include / exclude">${c.op.includes("contains") ? (c.op === "contains" ? "∋" : "∌") : c.op}</span>
          <span class="val">${c.value}</span>
          <button data-chip-del="${i}" aria-label="Remove filter">${icon("x")}</button></span>`)}
        <input class="kw-input" id="kwInput" aria-label="Keyword search"
          style="flex:1;min-width:180px;background:transparent;border:0;outline:none;font-size:15px;letter-spacing:.04em;color:#fff"
          placeholder="${state.chips.length ? "Add keyword…" : "Click a field on the left to add a filter…"}">`);
      return;
    }
    area.style.padding = "0";
    setHTML(area, html`<div class="q-editor">
      <pre aria-hidden="true" id="qHl"></pre>
      <textarea id="qInput" spellcheck="false" autocomplete="off" rows="1" aria-label="Query"
        placeholder='e.g. source_address="172.16.20.69" AND process=*powershell* | sort timestamp asc'></textarea>
      <button class="icon-btn sm q-help-btn" id="qHelp" title="Query language reference" aria-label="Query language reference">${icon("help")}</button>
      <div class="dropdown q-suggest hidden" id="qSuggest"></div>
    </div>`);
    const ta = $("qInput");
    ta.value = state.pro;
    renderEditorHighlight();
    autoSize();
  }

  function renderEditorHighlight() {
    const hl = $("qHl");
    if (!hl) return;
    const errPos = state.error?.pos ?? null;
    hl.innerHTML = highlightQuery(state.pro, state.fields.map((f) => f.name), errPos);
  }
  function autoSize() {
    const ta = $("qInput");
    if (!ta) return;
    ta.style.height = "auto";
    ta.style.height = ta.scrollHeight + "px";
  }

  function renderError() {
    const e = state.error;
    setHTML($("qError"), e ? html`<div class="error-box"><b>Query error${e.pos != null ? ` at position ${e.pos + 1}` : ""}:</b> ${e.message}</div>` : "");
  }

  function renderTime() {
    const t = state.time;
    const label = t.preset === "custom" ? "Custom" : TIME_PRESETS.find((p) => p.key === t.preset).label;
    setHTML($("timeBtn"), html`${label} ${icon("chevDown")}`);
    setHTML($("timeMenu"), html`
      ${TIME_PRESETS.map((p) => html`<button class="item ${t.preset === p.key ? "sel" : ""}" data-preset="${p.key}">${p.label}</button>`)}
      <div class="sep"></div>
      <div class="custom">
        <span class="field-label" style="margin:0">Custom range (UTC+03:00)</span>
        <input type="datetime-local" step="1" class="input" id="tFrom" value="${t.from.replace(" ", "T")}" aria-label="From">
        <input type="datetime-local" step="1" class="input" id="tTo" value="${t.to.replace(" ", "T")}" aria-label="To">
        <button class="btn btn-primary btn-sm" data-apply-custom>Apply</button>
      </div>`);
  }

  function renderMeta() {
    const r = state.result;
    setHTML($("meta"), r ? html`<div class="results-meta">${icon("check")} ${r.total.toLocaleString()} events found
      <span class="took">in ${r.took_ms} ms</span></div>` : "");
    $("countBadge").textContent = r ? r.total : 0;
  }

  function renderHist() {
    const h = state.hist;
    if (!h?.buckets?.length || h.buckets.length < 2) { setHTML($("hist"), ""); return; }
    const W = 1000, H = 70, n = h.buckets.length;
    const max = Math.max(...h.buckets.map((b) => b.count));
    const bw = W / n;
    const bars = h.buckets.map((b, i) => {
      const bh = Math.max(2, (b.count / max) * (H - 4));
      return `<rect class="bar" data-bucket="${esc(b.bucket)}" data-count="${b.count}" x="${(i * bw + bw * 0.1).toFixed(2)}" y="${(H - bh).toFixed(2)}" width="${Math.max(1, bw * 0.8).toFixed(2)}" height="${bh.toFixed(2)}"></rect>`;
    }).join("");
    setHTML($("hist"), html`<div class="histogram" title="Click a bar to zoom into that ${h.interval}">
        <svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" role="img" aria-label="Event count per ${h.interval}">${raw(bars)}</svg></div>
      <div class="hist-axis"><span>${h.buckets[0].bucket}</span><span>per ${h.interval}</span><span>${h.buckets[n - 1].bucket}</span></div>`);
  }

  function renderPager() {
    const r = state.result;
    setHTML($("pagerTop"), r && r.total ? pager(state.page, r.pages, { boxed: true }) : "");
  }

  function renderFields() {
    const side = $("fieldsSide");
    $("logsBody").classList.toggle("fields-hidden", state.fieldsHidden);
    if (state.fieldsHidden) {
      setHTML(side, html`<button class="hide-btn" data-toggle-fields>${icon("chevRight")} Show Fields</button>`);
      return;
    }
    const active = new Set(state.chips.map((c) => c.field));
    setHTML(side, html`<button class="hide-btn" data-toggle-fields>${icon("chevLeft")} Hide Fields</button>
      <h4>Interesting Fields</h4>
      ${state.fields.filter((f) => !f.hidden).map((f) => html`<button class="fld ${active.has(f.name) ? "hl" : ""}" data-field="${f.name}">
        <span class="t">${f.kind === "int" ? "#" : "α"}</span>${f.name}</button>`)}`);
  }

  function eventLine(ev, terms) {
    const src = ev.source_address ? ev.source_address + (ev.source_port ? ":" + ev.source_port : "") : "-";
    const dst = ev.destination_address ? ev.destination_address + (ev.destination_port ? ":" + ev.destination_port : "") : "-";
    return raw(`${esc(ev.timestamp)} | ${esc(ev.type)} | ${esc(src)} → ${esc(dst)} | ${highlight(ev.raw_log, terms)}`);
  }

  function renderEvents() {
    const box = $("events");
    if (state.loading && !state.result) { setHTML(box, loading()); return; }
    const r = state.result;
    if (!r) { box.innerHTML = ""; return; }
    if (!r.events.length) { setHTML(box, emptyState(state.error ? "Fix the query and search again" : "No events match your search", "search")); return; }
    const terms = r.terms || [];
    setHTML(box, r.events.map((ev) => {
      const open = state.open.has(ev.id);
      return html`<div class="ev ${open ? "open" : ""}" data-ev="${ev.id}">
        <div class="ev-line" data-toggle-ev="${ev.id}" role="button" tabindex="0" aria-expanded="${open}">
          <span class="chev">${icon("chevDown")}</span><span class="txt">${eventLine(ev, terms)}</span></div>
        ${open ? html`<div class="ev-body">
          <div class="kv">${Object.entries(ev).filter(([k, v]) => v !== null && v !== "" && k !== "raw_log" && k !== "id")
            .map(([k, v]) => html`<div class="k">${k}</div><div class="v"><span>${v}</span>
              <span class="mini"><button title="Include" aria-label="Include ${k}" data-add="${k}" data-op="=" data-val="${v}">${icon("plus")}</button>
              <button title="Exclude" aria-label="Exclude ${k}" data-add="${k}" data-op="!=" data-val="${v}">${icon("minus")}</button></span></div>`)}
          </div>
          <div class="raw-block">${raw(highlight(ev.raw_log, terms))}</div>
        </div>` : ""}
      </div>`;
    }));
  }

  function renderFiltersMenu() {
    setHTML($("filtersMenu"), html`
      <div class="opt-row"><span>Events per page</span>
        <select class="select" data-pagesize style="height:30px">${[20, 50, 100].map((n) => html`<option ${raw(n === state.pageSize ? "selected" : "")}>${n}</option>`)}</select></div>
      <div class="opt-row"><span>Order</span>
        <select class="select" data-order style="height:30px">
          <option value="desc" ${raw(state.sortAsc ? "" : "selected")}>Newest first</option>
          <option value="asc" ${raw(state.sortAsc ? "selected" : "")}>Oldest first</option></select></div>
      <div class="sep"></div>
      <button class="item" data-clear-all>Clear query & time range</button>`);
  }

  /* ---------- filters from fields / events ---------- */
  function addFilter(field, op, value) {
    if (state.mode === "basic") {
      if (!state.chips.some((c) => c.field === field && c.op === op && String(c.value) === String(value))) {
        state.chips.push({ field, op, value: String(value) });
      }
      renderQueryArea(); renderFields();
    } else {
      const clause = chipToQuery({ field, op, value });
      const cur = state.pro.trim();
      const [head, ...pipes] = cur.split(/(?=\|)/);
      const base = head.trim();
      state.pro = (base ? `${/\bOR\b/i.test(base) ? `(${base})` : base} AND ${clause}` : clause) + (pipes.length ? " " + pipes.join("").trim() : "");
      renderQueryArea();
    }
    search({ resetPage: true });
  }

  async function openFieldPopover(btn, field) {
    closePopover();
    const rect = btn.getBoundingClientRect();
    popover = document.createElement("div");
    popover.className = "dropdown field-pop";
    popover.style.left = Math.min(rect.right + 8, innerWidth - 376) + "px";
    popover.style.top = Math.max(8, Math.min(rect.top - 10, innerHeight - 430)) + "px";
    setHTML(popover, loading());
    document.body.appendChild(popover);
    const pop = popover;
    try {
      const data = await api.get(`/logs/fields/${field}/top`, { q: effectiveQuery(), ...timeParams() });
      if (pop !== popover) return;
      if (field === "raw_log") {
        setHTML(pop, html`<div class="fp-head"><b>raw_log</b><span class="muted small">free text</span></div>
          <div style="padding:6px 8px;display:grid;gap:8px"><span class="muted small">Add a keyword filter on the raw event text:</span>
          <input class="input" id="rawKw" placeholder="e.g. powershell"><button class="btn btn-primary btn-sm" data-raw-add>Add filter</button></div>`);
        pop.querySelector("#rawKw").focus();
        return;
      }
      setHTML(pop, html`<div class="fp-head"><b>${data.field}</b><span class="muted small">${data.distinct} distinct values · top ${data.values.length}</span></div>
        ${data.values.length ? data.values.map((v) => html`<div class="val-row clickable" data-add="${field}" data-op="=" data-val="${v.value}" title="${v.value}">
          <span class="v">${v.value}</span><span class="muted">${v.count} (${v.percent}%)</span>
          <span class="acts"><button title="Include" aria-label="Include" data-add="${field}" data-op="=" data-val="${v.value}">${icon("plus")}</button>
            <button title="Exclude" aria-label="Exclude" data-add="${field}" data-op="!=" data-val="${v.value}">${icon("minus")}</button></span>
          <span class="bar"><i style="width:${v.percent}%"></i></span></div>`) : emptyState("No values in current results")}`);
    } catch (e) {
      setHTML(pop, html`<div class="error-box">${e.message}</div>`);
    }
    pop.addEventListener("click", (e) => {
      const t = e.target.closest("[data-add],[data-raw-add]");
      if (!t) return;
      e.stopPropagation();
      if (t.hasAttribute("data-raw-add")) {
        const v = pop.querySelector("#rawKw").value.trim();
        if (v) addFilter("raw_log", "contains", v);
      } else addFilter(t.dataset.add, t.dataset.op, t.dataset.val);
      closePopover();
    });
    pop.addEventListener("keydown", (e) => {
      if (e.key === "Enter" && e.target.id === "rawKw") pop.querySelector("[data-raw-add]").click();
    });
  }
  function closePopover() { popover?.remove(); popover = null; }

  /* ---------- Pro editor autocomplete ---------- */
  function currentWord(ta) {
    const pos = ta.selectionStart;
    const before = ta.value.slice(0, pos);
    if ((before.match(/"/g) || []).length % 2) return null;       // inside a string
    const m = before.match(/([A-Za-z_][\w]*)$/);
    return m ? { word: m[1], start: pos - m[1].length, end: pos } : null;
  }
  function updateSuggest() {
    const ta = $("qInput"), box = $("qSuggest");
    if (!ta || !box) return;
    const cw = currentWord(ta);
    const w = cw?.word.toLowerCase();
    const candidates = w ? [
      ...state.fields.map((f) => ({ text: f.name, hint: f.kind === "int" ? "number" : f.kind === "time" ? "time" : "field" })),
      ...KEYWORDS.map((k) => ({ text: k, hint: "operator" })),
      ...COMMANDS.map((c) => ({ text: c, hint: "command" })),
    ].filter((c) => c.text.toLowerCase().startsWith(w) && c.text.toLowerCase() !== w).slice(0, 7) : [];
    suggest = { items: candidates, index: 0, open: candidates.length > 0, cw };
    box.classList.toggle("hidden", !suggest.open);
    if (suggest.open) {
      setHTML(box, candidates.map((c, i) => html`<button class="item ${i === 0 ? "sel" : ""}" data-sug="${i}"><span>${c.text}</span><span class="muted small">${c.hint}</span></button>`));
    }
  }
  function acceptSuggest(i = suggest.index) {
    const ta = $("qInput"), s = suggest.items[i];
    if (!ta || !s) return;
    const { start, end } = suggest.cw;
    const insert = s.hint === "operator" || s.hint === "command" ? s.text + " " : s.text;
    ta.value = ta.value.slice(0, start) + insert + ta.value.slice(end);
    ta.selectionStart = ta.selectionEnd = start + insert.length;
    state.pro = ta.value;
    closeSuggest(); renderEditorHighlight(); autoSize(); ta.focus();
  }
  function closeSuggest() { suggest.open = false; $("qSuggest")?.classList.add("hidden"); }

  function showCheatsheet() {
    modal({
      title: "Query Language Reference", wide: true, hideFooter: true,
      body: html`<div class="cheatsheet">
        <table>
          <tr><td><code>field=value</code> <code>field!=value</code></td><td>Equality (case-insensitive). Use quotes for spaces: <code>process="C:\\Windows\\x.exe"</code></td></tr>
          <tr><td><code>field=*part*</code></td><td>Wildcard with <code>*</code></td></tr>
          <tr><td><code>&gt; &gt;= &lt; &lt;=</code></td><td>Numeric / time comparison (ports, id, timestamp)</td></tr>
          <tr><td><code>field IN (a, b)</code> <code>field NOT IN (…)</code></td><td>Match a list of values</td></tr>
          <tr><td><code>CONTAINS</code> <code>STARTSWITH</code> <code>ENDSWITH</code></td><td>Substring operators</td></tr>
          <tr><td><code>field EXISTS</code></td><td>Field is present / non-empty</td></tr>
          <tr><td><code>AND</code> <code>OR</code> <code>NOT</code> <code>( )</code></td><td>Boolean logic. Whitespace between terms = AND. <code>!</code> = NOT</td></tr>
          <tr><td><code>keyword</code> <code>"two words"</code></td><td>Free-text search in <code>raw_log</code> (highlighted in results)</td></tr>
          <tr><td><code>| sort field [asc|desc]</code> <code>| head N</code></td><td>Pipe commands: order results, limit count</td></tr>
          <tr><td>Fields</td><td>${state.fields.map((f) => html`<code>${f.name}</code> `)}<br><span class="muted">Aliases: src, dst, sport, dport, host, user, image, cmd, raw, time</span></td></tr>
        </table>
        <h3 style="margin:18px 0 8px;font-size:13px;color:var(--teal-2);letter-spacing:.08em">EXAMPLES (click to use)</h3>
        <table>${EXAMPLES.map(([q, d]) => html`<tr><td><button class="example" data-example="${q}"><code>${q}</code></button></td><td class="muted">${d}</td></tr>`)}</table>
      </div>`,
    }).el.addEventListener("click", (e) => {
      const b = e.target.closest("[data-example]");
      if (!b) return;
      state.pro = b.dataset.example;
      e.currentTarget.remove();
      renderQueryArea();
      search({ resetPage: true });
    });
  }

  /* ---------- mode switching ---------- */
  function setMode(mode) {
    if (mode === state.mode) return;
    if (mode === "pro") {
      state.pro = chipsToQuery(state.chips);
      finishMode(mode);
    } else {
      const chips = queryToChips(state.pro);
      if (chips) { state.chips = chips; finishMode(mode); return; }
      modal({
        title: "Switch to Basic mode?",
        body: html`<p>This query uses operators Basic mode can't show as filters (OR, parentheses, pipes, comparisons…).</p>
          <p class="muted">Switching will clear the current query.</p>`,
        confirmText: "Clear & switch", danger: true,
        onConfirm: () => { state.chips = []; finishMode(mode); search({ resetPage: true }); },
      });
    }
  }
  function finishMode(mode) {
    state.mode = mode;
    state.error = null;
    try { localStorage.setItem("soc.logs.mode", mode); } catch { }
    renderMode(); renderFields(); renderError(); syncUrl();
    if (mode === "pro") $("qInput")?.focus();
  }

  /** Apply #/logs?mode=..&q=.. (pivots from other pages). Returns true when a search was started. */
  function applyParams(p) {
    if (p.q === undefined && !p.mode) return false;    // plain sidebar navigation: keep current state
    const q = p.q ?? "";
    const mode = p.mode === "pro" ? "pro" : p.mode === "basic" ? "basic" : state.mode;
    const cur = state.mode === "basic" ? chipsToQuery(state.chips) : state.pro;
    if (mode === state.mode && q === cur) return false;
    if (mode === "basic") {
      const chips = queryToChips(q);
      if (chips) { state.mode = "basic"; state.chips = chips; }
      else { state.mode = "pro"; state.pro = q; }
    } else { state.mode = "pro"; state.pro = q; }
    renderMode(); renderFields();
    search({ resetPage: true });
    return true;
  }

  /* ---------- events ---------- */
  el.addEventListener("click", (e) => {
    const t = e.target.closest("button, [data-toggle-ev], [data-add], .bar");
    if (!t) return;
    const d = t.dataset;
    if (d.mode) setMode(d.mode);
    else if (t.id === "searchBtn") { closeSuggest(); search({ resetPage: true }); }
    else if (t.id === "timeBtn") { $("timeMenu").classList.toggle("hidden"); $("filtersMenu").classList.add("hidden"); }
    else if (d.preset) {
      state.time = { preset: d.preset, from: "", to: "" };
      $("timeMenu").classList.add("hidden"); renderTime(); search({ resetPage: true });
    } else if (t.hasAttribute("data-apply-custom")) {
      const from = $("tFrom").value.replace("T", " "), to = $("tTo").value.replace("T", " ");
      if (!from && !to) { toast("Pick a start or end time", "error"); return; }
      if (from && to && from > to) { toast("Start time must be before end time", "error"); return; }
      state.time = { preset: "custom", from, to };
      $("timeMenu").classList.add("hidden"); renderTime(); search({ resetPage: true });
    } else if (t.id === "filtersBtn") {
      renderFiltersMenu(); $("filtersMenu").classList.toggle("hidden"); $("timeMenu").classList.add("hidden");
    } else if (t.hasAttribute("data-clear-all")) {
      state.chips = []; state.pro = ""; state.time = { preset: "all", from: "", to: "" };
      $("filtersMenu").classList.add("hidden");
      renderQueryArea(); renderTime(); renderFields(); search({ resetPage: true });
    } else if (d.page) {
      if (t.disabled) return;
      state.page = Number(d.page); search();
    } else if (d.field) {
      openFieldPopover(t, d.field);
    } else if (t.hasAttribute("data-toggle-fields")) {
      state.fieldsHidden = !state.fieldsHidden; renderFields();
    } else if (d.chipDel !== undefined) {
      state.chips.splice(Number(d.chipDel), 1);
      renderQueryArea(); renderFields(); search({ resetPage: true });
    } else if (d.toggleEv) {
      const id = Number(d.toggleEv);
      state.open.has(id) ? state.open.delete(id) : state.open.add(id);
      renderEvents();
    } else if (d.add) {
      e.stopPropagation();
      addFilter(d.add, d.op, d.val);
    } else if (t.id === "qHelp") showCheatsheet();
    else if (d.sug !== undefined) acceptSuggest(Number(d.sug));
  });

  // chip operator toggle (span, not a button)
  el.addEventListener("click", (e) => {
    const op = e.target.closest("[data-chip-op]");
    if (!op) return;
    const c = state.chips[Number(op.dataset.chipOp)];
    c.op = { "=": "!=", "!=": "=", contains: "!contains", "!contains": "contains" }[c.op];
    renderQueryArea(); search({ resetPage: true });
  });

  // histogram: tooltip + click-to-zoom
  const tip = document.createElement("div");
  tip.className = "tooltip hidden";
  document.body.appendChild(tip);
  el.addEventListener("mousemove", (e) => {
    const bar = e.target.closest?.("rect.bar");
    if (!bar) { tip.classList.add("hidden"); return; }
    tip.textContent = `${bar.dataset.bucket}  ·  ${bar.dataset.count} events`;
    tip.style.left = e.clientX + 12 + "px"; tip.style.top = e.clientY - 30 + "px";
    tip.classList.remove("hidden");
  });
  el.addEventListener("click", (e) => {
    const bar = e.target.closest?.("rect.bar");
    if (!bar) return;
    const b = bar.dataset.bucket;
    const ranges = {
      7: [b + "-01 00:00:00", b + "-31 23:59:59"], 10: [b + " 00:00:00", b + " 23:59:59"],
      13: [b + ":00:00", b + ":59:59"], 16: [b + ":00", b + ":59"],
    };
    const [from, to] = ranges[b.length];
    state.time = { preset: "custom", from, to };
    tip.classList.add("hidden");
    renderTime(); search({ resetPage: true });
  });

  el.addEventListener("change", (e) => {
    if (e.target.matches("[data-pagesize]")) { state.pageSize = Number(e.target.value); search({ resetPage: true }); }
    if (e.target.matches("[data-order]")) { state.sortAsc = e.target.value === "asc"; search({ resetPage: true }); }
  });

  el.addEventListener("input", (e) => {
    if (e.target.id === "qInput") {
      state.pro = e.target.value;
      if (state.error) { state.error = null; renderError(); }
      renderEditorHighlight(); autoSize(); updateSuggest();
    }
  });

  el.addEventListener("keydown", (e) => {
    if (e.target.id === "qInput") {
      if (suggest.open) {
        if (e.key === "ArrowDown" || e.key === "ArrowUp") {
          e.preventDefault();
          suggest.index = (suggest.index + (e.key === "ArrowDown" ? 1 : -1) + suggest.items.length) % suggest.items.length;
          $("qSuggest").querySelectorAll(".item").forEach((b, i) => b.classList.toggle("sel", i === suggest.index));
          return;
        }
        if (e.key === "Tab" || e.key === "Enter") { e.preventDefault(); acceptSuggest(); return; }
        if (e.key === "Escape") { closeSuggest(); return; }
      }
      if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); search({ resetPage: true }); }
    } else if (e.target.id === "kwInput" && e.key === "Enter") {
      const v = e.target.value.trim();
      if (v) addFilter("raw_log", "contains", v);
      else search({ resetPage: true });
    } else if (e.target.id === "kwInput" && e.key === "Backspace" && !e.target.value && state.chips.length) {
      state.chips.pop(); renderQueryArea(); renderFields(); $("kwInput").focus(); search({ resetPage: true });
    } else if (e.target.matches("[data-toggle-ev]") && (e.key === "Enter" || e.key === " ")) {
      e.preventDefault(); e.target.click();
    }
  });
  // keep editor focus while clicking a suggestion
  el.addEventListener("mousedown", (e) => { if (e.target.closest("#qSuggest")) e.preventDefault(); });
  el.addEventListener("focusout", debounce(() => { if (document.activeElement?.id !== "qInput") closeSuggest(); }, 150));

  const onDocClick = (e) => {
    if (popover && !popover.contains(e.target) && !e.target.closest("[data-field]")) closePopover();
    if (!e.target.closest(".time-picker")) $("timeMenu")?.classList.add("hidden");
    if (!e.target.closest(".toolbar > div:first-child")) $("filtersMenu")?.classList.add("hidden");
  };
  document.addEventListener("mousedown", onDocClick);
  const onScroll = () => closePopover();
  window.addEventListener("scroll", onScroll, true);

  /* ---------- init ---------- */
  instance = { applyParams };
  renderMode(); renderTime(); renderFields();
  api.get("/logs/fields").then((f) => { state.fields = f; renderFields(); renderEditorHighlight(); })
    .catch((e) => toast(e.message, "error"));
  if (!applyParams(params)) search();

  return () => {
    ctrl?.abort();
    closePopover();
    tip.remove();
    document.removeEventListener("mousedown", onDocClick);
    window.removeEventListener("scroll", onScroll, true);
    instance = null;
  };
}
