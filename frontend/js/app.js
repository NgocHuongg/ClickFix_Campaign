import { api, loadSession, session } from "./api.js";
import { html, icon, setHTML, toast } from "./utils.js";
import * as landing from "./views/landing.js";
import * as authViews from "./views/auth.js";
import * as monitoring from "./views/monitoring.js";
import * as logs from "./views/logs.js";
import * as cases from "./views/cases.js";
import * as endpoints from "./views/endpoints.js";
import * as intel from "./views/intel.js";
import * as email from "./views/email.js";
import * as sandbox from "./views/sandbox.js";

const PUBLIC = [
  { path: "/", label: "SOC Simulation", view: landing },
  { path: "/login", label: "Sign in", view: authViews.login, guestOnly: true },
  { path: "/register", label: "Create account", view: authViews.register, guestOnly: true },
];
const ROUTES = [
  { path: "/monitoring", label: "Monitoring", icon: "monitor", view: monitoring },
  { path: "/logs", label: "Log Management", icon: "list", view: logs },
  { path: "/cases", label: "Case Management", icon: "clipboard", view: cases },
  { path: "/endpoints", label: "Endpoint Security", icon: "hdd", view: endpoints },
  { path: "/intel", label: "Threat Intel", icon: "shield", view: intel },
  { path: "/email", label: "Email Security", icon: "mail", view: email },
  { path: "/sandbox", label: "Sandbox", icon: "box", view: sandbox },
];

const appEl = document.getElementById("app");
const nav = document.getElementById("nav");
const viewEl = document.getElementById("view");
const footEl = document.getElementById("sidebarFoot");
let cleanup = null;
let current = null;

setHTML(nav, ROUTES.map((r) => html`<a href="#${r.path}" data-path="${r.path}" title="${r.label}">
  ${icon(r.icon)}<span class="label">${r.label}</span></a>`));

try {
  if (localStorage.getItem("soc.sidebar") === "collapsed") appEl.classList.add("collapsed");
} catch { /* storage unavailable */ }
document.getElementById("collapseBtn").addEventListener("click", () => {
  appEl.classList.toggle("collapsed");
  try { localStorage.setItem("soc.sidebar", appEl.classList.contains("collapsed") ? "collapsed" : "open"); } catch { }
});

function renderUser() {
  const u = session.user;
  if (!u) { footEl.innerHTML = ""; return; }
  const initials = u.full_name.split(/\s+/).map((p) => p[0]).slice(0, 2).join("").toUpperCase();
  setHTML(footEl, html`<div class="avatar">${initials}</div>
    <div class="label" style="min-width:0;flex:1"><div class="who">${u.full_name}</div><div class="muted small">${u.role}</div></div>
    <button class="icon-btn sm label" id="logoutBtn" title="Sign out" aria-label="Sign out">${icon("logout")}</button>`);
}
footEl.addEventListener("click", async (e) => {
  if (!e.target.closest("#logoutBtn")) return;
  try { await api.post("/auth/logout"); } catch { /* already gone */ }
  session.user = null;
  toast("Signed out");
  location.hash = "#/";
});

function parseHash() {
  const h = location.hash.slice(1) || "/";
  const [path, qs = ""] = h.split("?");
  return { path: path || "/", params: Object.fromEntries(new URLSearchParams(qs)) };
}

function mountView(r, params) {
  cleanup?.();
  current = r;
  // Fresh container per mount so listeners from the previous view die with its element.
  const host = document.createElement("div");
  viewEl.replaceChildren(host);
  window.scrollTo(0, 0);
  cleanup = r.view.mount(host, params) || null;
}

function route() {
  const { path, params } = parseHash();
  const pub = PUBLIC.find((x) => x.path === path);
  const r = pub || ROUTES.find((x) => x.path === path);
  if (!r) { location.replace(session.user ? "#/monitoring" : "#/"); return; }

  if (!pub && !session.user) {
    location.replace("#/login?" + new URLSearchParams({ next: location.hash.slice(1) }));
    return;
  }
  if (pub?.guestOnly && session.user) { location.replace("#/monitoring"); return; }

  appEl.classList.toggle("public", !!pub);
  renderUser();
  nav.querySelectorAll("a").forEach((a) => a.classList.toggle("active", a.dataset.path === r.path));
  document.title = pub ? (r.path === "/" ? "SOC Simulation · Train like a real SOC analyst" : `${r.label} · SOC Simulation`)
    : `${r.label} · SOC Simulation`;
  // Same view + the view can react to param changes itself (e.g. logs pivot): let it update in place.
  if (current === r && r.view.update && r.view.update(params) !== false) return;
  mountView(r, params);
}

// Session expired while using the console -> back to login, then return to the same page.
window.addEventListener("soc:unauthorized", () => {
  if (!session.user) return;
  session.user = null;
  toast("Your session has expired. Please sign in again.", "error");
  location.hash = "#/login?" + new URLSearchParams({ next: location.hash.slice(1) });
});
window.addEventListener("hashchange", route);

loadSession().then(route);
