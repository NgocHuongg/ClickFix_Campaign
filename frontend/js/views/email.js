import { api } from "../api.js";
import { debounce, emptyState, html, icon, isoTz, loading, logsLink, setHTML, toast } from "../utils.js";

const ACTION_BADGE = { Allowed: "green", Blocked: "red", Quarantined: "orange", Deleted: "" };

export function mount(el) {
  const state = { items: [], selected: null, search: "" };
  setHTML(el, html`
    <div class="page-head"><div><h1 class="page-title">Email Security</h1>
      <p class="page-sub">Inspect delivered mail, headers and attachments. Quarantine or block suspicious messages.</p></div></div>
    <div class="split">
      <section class="panel">
        <div class="list-tools"><div class="search-input">${icon("search")}<input class="input" data-search placeholder="Sender, recipient, subject, SMTP IP…"></div></div>
        <div class="list" id="mailList">${loading()}</div>
      </section>
      <section class="panel detail" id="mailDetail"></section>
    </div>`);
  const listEl = el.querySelector("#mailList"), detailEl = el.querySelector("#mailDetail");

  async function load() {
    try { state.items = await api.get("/emails", { search: state.search }); }
    catch (e) { setHTML(listEl, html`<div class="error-box">${e.message}</div>`); return; }
    if (!state.items.some((m) => m.id === state.selected)) state.selected = state.items[0]?.id ?? null;
    render();
  }

  function render() {
    setHTML(listEl, state.items.length ? state.items.map((m) => html`
      <div class="list-item ${m.id === state.selected ? "sel" : ""}" data-id="${m.id}" tabindex="0">
        <div class="row1"><span class="title">${m.subject}</span><span class="badge ${ACTION_BADGE[m.action]}">${m.action}</span></div>
        <div class="meta"><span>${m.sender}</span>${m.attachments.length ? html`<span>${icon("paperclip")}</span>` : ""}<span>${m.received_at}</span></div>
      </div>`) : emptyState("No messages", "mail"));
    const m = state.items.find((x) => x.id === state.selected);
    if (!m) { setHTML(detailEl, emptyState("Select a message", "mail")); return; }
    setHTML(detailEl, html`
      <div class="detail-head"><div><h2>${m.subject}</h2><span class="badge ${ACTION_BADGE[m.action]}">${m.action}</span></div>
        <div class="btn-row">
          <button class="btn btn-sm" data-action="Quarantined">${icon("inbox")} Quarantine</button>
          <button class="btn btn-sm btn-danger" data-action="Blocked">${icon("ban")} Block</button>
          <button class="btn btn-sm" data-action="Deleted">${icon("trash")} Delete</button>
          ${m.action !== "Allowed" ? html`<button class="btn btn-sm btn-ghost" data-action="Allowed">Release</button>` : ""}
        </div></div>
      <div class="kv">
        <div class="k">From</div><div class="v mono">${m.sender}</div>
        <div class="k">To</div><div class="v mono">${m.recipient}</div>
        <div class="k">Date</div><div class="v">${isoTz(m.received_at)}</div>
        <div class="k">SMTP Address</div><div class="v mono"><a href="${logsLink(`raw_log CONTAINS "${m.smtp_ip}"`)}">${m.smtp_ip}</a></div>
      </div>
      <h3>Body</h3><div class="email-body">${m.body}</div>
      <h3>Attachments</h3>
      ${m.attachments.length ? m.attachments.map((a) => html`<div class="attachment">${icon("file")}
          <div style="flex:1;min-width:0"><div>${a.name}</div><div class="muted small mono">MD5 ${a.md5} · ${(a.size / 1024).toFixed(0)} KB</div></div>
          <a class="btn btn-sm" href="#/sandbox?search=${encodeURIComponent(a.name)}">${icon("box")} Sandbox</a></div>`)
        : html`<p class="muted">No attachments</p>`}`);
  }

  el.addEventListener("click", async (e) => {
    const item = e.target.closest(".list-item");
    if (item) { state.selected = Number(item.dataset.id); render(); return; }
    const b = e.target.closest("[data-action]");
    if (b) {
      try {
        const upd = await api.post(`/emails/${state.selected}/action`, { action: b.dataset.action });
        Object.assign(state.items.find((x) => x.id === upd.id), upd);
        toast(`Message marked as ${upd.action}`); render();
      } catch (err) { toast(err.message, "error"); }
    }
  });
  el.addEventListener("keydown", (e) => { if (e.key === "Enter" && e.target.matches(".list-item")) e.target.click(); });
  const onSearch = debounce(load, 300);
  el.addEventListener("input", (e) => { if (e.target.matches("[data-search]")) { state.search = e.target.value; onSearch(); } });
  load();
}
