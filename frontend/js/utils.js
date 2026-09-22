import { PLATFORM_TZ } from "./config.js";

/* ---------- safe HTML templating (auto-escapes every interpolated value) ---------- */
class SafeHTML {
  constructor(s) { this.s = s; }
  toString() { return this.s; }
}
export const raw = (s) => new SafeHTML(String(s));

const ESC = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
export const esc = (v) => String(v).replace(/[&<>"']/g, (c) => ESC[c]);

function render(v) {
  if (v === null || v === undefined || v === false) return "";
  if (v instanceof SafeHTML) return v.s;
  if (Array.isArray(v)) return v.map(render).join("");
  return esc(v);
}
export function html(strings, ...values) {
  let out = strings[0];
  values.forEach((v, i) => { out += render(v) + strings[i + 1]; });
  return new SafeHTML(out);
}
/** Arrays are joined without separators (String([a, b]) would insert commas). */
export function setHTML(el, content) { el.innerHTML = render(content); }

/* ---------- icons (lucide-style, stroke = currentColor) ---------- */
const P = {
  monitor: '<rect x="2" y="3" width="20" height="14" rx="2"/><path d="m8 21 4-4 4 4"/><path d="M7 10l3-3 3 3 4-4"/>',
  list: '<path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/>',
  clipboard: '<rect x="6" y="3" width="12" height="18" rx="2"/><path d="M9 3h6v3H9z"/>',
  hdd: '<path d="M22 12H2"/><path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"/><path d="M6 16h.01M10 16h.01"/>',
  shield: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
  mail: '<rect x="2" y="4" width="20" height="16" rx="2"/><path d="m22 7-10 6L2 7"/>',
  box: '<path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/><path d="M3.3 7 12 12l8.7-5M12 22V12"/><path d="m7.5 4.2 9 5.2"/>',
  chevDown: '<path d="m6 9 6 6 6-6"/>',
  chevLeft: '<path d="m15 18-6-6 6-6"/>',
  chevRight: '<path d="m9 18 6-6-6-6"/>',
  userPlus: '<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M19 8v6M22 11h-6"/>',
  sliders: '<path d="M4 21v-7M4 10V3M12 21v-9M12 8V3M20 21v-5M20 12V3M1 14h6M9 8h6M17 16h6"/>',
  search: '<circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/>',
  check: '<path d="M20 6 9 17l-5-5"/>',
  checkCircle: '<circle cx="12" cy="12" r="10"/><path d="m9 12 2 2 4-4"/>',
  x: '<path d="M18 6 6 18M6 6l12 12"/>',
  info: '<circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/>',
  filter: '<path d="M22 3H2l8 9.46V19l4 2v-8.54L22 3z"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  minus: '<path d="M5 12h14"/>',
  undo: '<path d="M9 14 4 9l5-5"/><path d="M4 9h10.5a5.5 5.5 0 0 1 0 11H11"/>',
  folderPlus: '<path d="M4 20h16a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.93a2 2 0 0 1-1.66-.9l-.82-1.2A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13c0 1.1.9 2 2 2z"/><path d="M12 10v6M9 13h6"/>',
  eye: '<path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7z"/><circle cx="12" cy="12" r="3"/>',
  lock: '<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>',
  unlock: '<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 9.9-1"/>',
  paperclip: '<path d="m21.44 11.05-9.19 9.19a6 6 0 0 1-8.49-8.49l8.57-8.57A4 4 0 1 1 18 8.84l-8.59 8.57a2 2 0 0 1-2.83-2.83l8.49-8.48"/>',
  file: '<path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z"/><path d="M14 2v6h6"/>',
  help: '<circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3M12 17h.01"/>',
  external: '<path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6M15 3h6v6M10 14 21 3"/>',
  trash: '<path d="M3 6h18M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>',
  ban: '<circle cx="12" cy="12" r="10"/><path d="m4.9 4.9 14.2 14.2"/>',
  terminal: '<path d="m4 17 6-6-6-6M12 19h8"/>',
  inbox: '<path d="M22 12h-6l-2 3h-4l-2-3H2"/><path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"/>',
  calendar: '<rect x="3" y="4" width="18" height="18" rx="2"/><path d="M16 2v4M8 2v4M3 10h18"/>',
  logout: '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9"/>',
  user: '<path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>',
  key: '<circle cx="7.5" cy="15.5" r="5.5"/><path d="m21 2-9.6 9.6M15.5 7.5l3 3L22 7l-3-3"/>',
  eyeOff: '<path d="M9.88 9.88a3 3 0 1 0 4.24 4.24M10.73 5.08A10.4 10.4 0 0 1 12 5c7 0 10 7 10 7a13.2 13.2 0 0 1-1.67 2.68M6.61 6.61A13.5 13.5 0 0 0 2 12s3 7 10 7a9.7 9.7 0 0 0 5.39-1.61M2 2l20 20"/>',
  arrowRight: '<path d="M5 12h14M12 5l7 7-7 7"/>',
  activity: '<path d="M22 12h-4l-3 9L9 3l-3 9H2"/>',
  zap: '<path d="M13 2 3 14h9l-1 8 10-12h-9l1-8z"/>',
  target: '<circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/>',
  alert: '<path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3z"/><path d="M12 9v4M12 17h.01"/>',
  atSign: '<circle cx="12" cy="12" r="4"/><path d="M16 8v5a3 3 0 0 0 6 0v-1a10 10 0 1 0-3.92 7.94"/>',
};
export const icon = (name, cls = "") =>
  raw(`<svg class="${cls}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${P[name] || ""}</svg>`);

/* ---------- formatting ---------- */
export const isoTz = (ts) => (ts ? ts.replace(" ", "T") + PLATFORM_TZ : "");
export const sevClass = (s) => `sev sev-${s}`;
/** Coloured severity pill: Critical red · High orange · Medium yellow · Low green. */
export const sevBadge = (s) => html`<span class="sev-badge sev-${s}"><span class="dot"></span>${s}</span>`;
export const verdictBadge = (v) =>
  v ? html`<span class="badge ${v === "True Positive" ? "red" : "green"}">${v}</span>` : "";
export const debounce = (fn, ms = 250) => {
  let t;
  return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); };
};
export function highlight(text, terms) {
  const s = String(text ?? "");
  const ts = (terms || []).filter(Boolean);
  if (!ts.length) return esc(s);
  const re = new RegExp(ts.map((t) => t.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|"), "gi");
  let out = "", last = 0;
  for (const m of s.matchAll(re)) {
    out += esc(s.slice(last, m.index)) + "<mark>" + esc(m[0]) + "</mark>";
    last = m.index + m[0].length;
  }
  return out + esc(s.slice(last));
}

/* ---------- pagination ---------- */
export function pageList(page, pages) {
  if (pages <= 7) return Array.from({ length: pages }, (_, i) => i + 1);
  const set = new Set([1, pages, page - 1, page, page + 1]);
  if (page <= 4) [2, 3, 4, 5].forEach((p) => set.add(p));
  if (page >= pages - 3) [pages - 4, pages - 3, pages - 2, pages - 1].forEach((p) => set.add(p));
  const arr = [...set].filter((p) => p >= 1 && p <= pages).sort((a, b) => a - b);
  const out = [];
  arr.forEach((p, i) => { if (i && p - arr[i - 1] > 1) out.push("…"); out.push(p); });
  return out;
}
export function pager(page, pages, { boxed = false } = {}) {
  return html`<div class="pager ${boxed ? "boxed" : ""}">
    <button class="nav-btn" data-page="${page - 1}" ${raw(page <= 1 ? "disabled" : "")} aria-label="Previous page">${icon("chevLeft")}</button>
    ${pageList(page, pages).map((p) => p === "…"
      ? html`<span class="gap">…</span>`
      : html`<button data-page="${p}" class="${p === page ? "active" : ""}">${p}</button>`)}
    <button class="nav-btn" data-page="${page + 1}" ${raw(page >= pages ? "disabled" : "")} aria-label="Next page">${icon("chevRight")}</button>
  </div>`;
}

/* ---------- toast ---------- */
export function toast(msg, type = "ok") {
  const el = document.createElement("div");
  el.className = `toast ${type === "error" ? "error" : ""}`;
  el.textContent = msg;
  document.getElementById("toasts").appendChild(el);
  setTimeout(() => el.remove(), 3500);
}

/* ---------- modal ---------- */
export function modal({ title, body, confirmText = "Confirm", cancelText = "Cancel", danger = false, wide = false,
  onConfirm, hideFooter = false }) {
  const root = document.getElementById("modalRoot");
  const wrap = document.createElement("div");
  wrap.className = "modal-backdrop";
  setHTML(wrap, html`<div class="modal ${wide ? "wide" : ""}" role="dialog" aria-modal="true" aria-label="${title}">
    <div class="modal-head"><h3>${title}</h3><button class="icon-btn sm" data-close aria-label="Close">${icon("x")}</button></div>
    <div class="modal-body">${body}</div>
    ${hideFooter ? "" : html`<div class="modal-foot">
      <button class="btn btn-ghost" data-close>${cancelText}</button>
      <button class="btn ${danger ? "btn-danger" : "btn-primary"}" data-ok>${confirmText}</button></div>`}
  </div>`);
  const close = () => { wrap.remove(); document.removeEventListener("keydown", onKey); };
  const onKey = (e) => { if (e.key === "Escape") close(); };
  document.addEventListener("keydown", onKey);
  wrap.addEventListener("mousedown", (e) => { if (e.target === wrap) close(); });
  wrap.querySelectorAll("[data-close]").forEach((b) => b.addEventListener("click", close));
  const ok = wrap.querySelector("[data-ok]");
  ok?.addEventListener("click", async () => {
    ok.disabled = true;
    try {
      const keep = await onConfirm?.(wrap.querySelector(".modal-body"));
      if (keep !== false) close();
    } catch (e) {
      toast(e.message, "error");
    } finally { ok.disabled = false; }
  });
  root.appendChild(wrap);
  wrap.querySelector("input, textarea, select, [data-ok]")?.focus();
  return { el: wrap, close };
}

export const loading = () => html`<div class="spinner" role="status" aria-label="Loading"></div>`;
export const emptyState = (text, ic = "inbox") => html`<div class="empty">${icon(ic)}<div>${text}</div></div>`;

/* hash-route helpers */
export function navigate(path, params) {
  const qs = params ? "?" + new URLSearchParams(Object.entries(params).filter(([, v]) => v !== "" && v != null)) : "";
  location.hash = "#" + path + qs;
}
export const logsLink = (q) => "#/logs?" + new URLSearchParams({ mode: "pro", q });
