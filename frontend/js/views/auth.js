import { api, session } from "../api.js";
import { html, icon, setHTML, sevBadge, toast } from "../utils.js";

const DEMO = { login: "analyst", password: "Analyst@123" };

/* ================= ClickFix fake reCAPTCHA (training widget) ================= */

const CLICKFIX_CSS_ID = "clickfix-captcha-css";
const CLICKFIX_CSS = `
.cf-wrap { margin: 14px 0 14px; }
.cf-checkbox-window {
  height: 74px; width: 300px;
  background: #f9f9f9; border-radius: 3px; border: 1px solid #d3d3d3;
  position: relative;
}
.cf-checkbox-container { width: 28px; height: 28px; }
.cf-checkbox {
  position: relative; background: #fff; border-radius: 2px;
  height: 100%; width: 100%; border: 2px solid #c1c1c1;
  margin: 21px 0 0 12px; outline: none; cursor: pointer;
  transition: width .5s, height .5s, border-radius .5s, margin .5s, opacity .7s;
}
.cf-checkbox:hover { border-color: #b2b2b2; }
.cf-checkbox.verified { border-color: #4285f4; }
.cf-checkbox.verified::after {
  content: "\\2713"; color: #4285f4; font-size: 22px; font-weight: bold;
  position: absolute; top: -1px; left: 6px; line-height: 28px;
}
.cf-label { position: absolute; left: 52px; top: 26px; font-size: 15px; color: #282727; margin: 0; }
.cf-logo { position: absolute; left: 244px; top: 18px; width: 40px; }
.cf-desc { position: absolute; left: 112px; bottom: 4px; font-size: 8px; color: #555; text-align: center; margin: 0; }
.cf-desc a { color: #555; text-decoration: none; }
.cf-desc a:hover { text-decoration: underline; }
.cf-spinner {
  position: absolute; top: 28px; left: 18px;
  height: 20px; width: 20px;
  border: 2px solid rgba(0,0,0,.1); border-top-color: #333;
  border-radius: 50%; opacity: 0; visibility: hidden;
  animation: cf-spin 1s linear infinite;
}
@keyframes cf-spin { to { transform: rotate(360deg); } }

.cf-modal {
  position: fixed; inset: 0; background: rgba(0,0,0,.55);
  display: none; align-items: center; justify-content: center;
  z-index: 9999;
}
.cf-modal.open { display: flex; }
.cf-verify-window {
  width: 380px; max-width: calc(100vw - 32px); background: #fff;
  box-shadow: 0 12px 40px rgba(0,0,0,.35);
  font-family: Roboto, helvetica, arial, sans-serif;
  border-radius: 4px; overflow: hidden;
}
.cf-verify-header { background: #1A73E8; padding: 16px 18px 20px; color: #fff; }
.cf-verify-header .small { font-size: 14px; display: block; opacity: .9; }
.cf-verify-header .big { font-size: 22px; font-weight: 700; display: block; margin-top: 2px; }
.cf-verify-main { padding: 18px; color: #111; font-size: 13.5px; line-height: 1.5; }
.cf-verify-main p { margin: 0 0 10px; }
.cf-verify-main ol { padding-left: 0; list-style: none; counter-reset: item; margin: 0 0 12px; }
.cf-verify-main ol li { counter-increment: item; margin-bottom: 8px; padding-left: 26px; position: relative; }
.cf-verify-main ol li::before {
  content: counter(item) "."; position: absolute; left: 0;
  color: #1A73E8; font-weight: bold;
}
.cf-verify-main code {
  display: block; background: #f1f3f4; padding: 10px;
  font-size: 11px; color: #444; word-break: break-all;
  border-radius: 3px; margin-top: 6px; font-family: monospace;
}
.cf-verify-footer {
  border-top: 1px solid #cecece; padding: 12px 16px;
  display: flex; align-items: center; justify-content: space-between;
  color: #737373; font-size: 12.5px; gap: 10px;
}
.cf-cancel {
  background: none; border: none; color: #737373; cursor: pointer;
  font-size: 12.5px; text-decoration: underline; padding: 6px;
}
.cf-verify-btn {
  text-transform: uppercase; background: #9bb7e8; color: #fff;
  border: none; padding: 10px 14px; border-radius: 3px;
  font-weight: 600; font-size: 12.5px; cursor: not-allowed;
}
.cf-verify-btn.ready { background: #1A73E8; cursor: pointer; }
`;

function ensureClickFixStyles() {
  if (document.getElementById(CLICKFIX_CSS_ID)) return;
  const s = document.createElement("style");
  s.id = CLICKFIX_CSS_ID;
  s.textContent = CLICKFIX_CSS;
  document.head.appendChild(s);
}

function clickFixWidgetHtml() {
  return html`
    <div class="cf-wrap">
      <div class="cf-checkbox-window" id="cf-window">
        <div class="cf-checkbox-container">
          <button type="button" id="cf-checkbox" class="cf-checkbox" aria-label="I'm not a robot"></button>
        </div>
        <p class="cf-label">I'm not a robot</p>
        <img src="https://www.google.com/recaptcha/about/images/reCAPTCHA-logo@2x.png" class="cf-logo" alt="">
        <p class="cf-desc">
          <a href="https://www.google.com/intl/en/policies/privacy/" target="_blank" rel="noopener">Privacy</a> -
          <a href="https://www.google.com/intl/en/policies/terms/" target="_blank" rel="noopener">Terms</a>
        </p>
        <span class="cf-spinner" id="cf-spinner"></span>
      </div>
      <div class="msg" data-msg="captcha" style="color:#ff8b8b;font-size:12.5px;margin-top:8px"></div>
    </div>
    <div class="cf-modal" id="cf-modal">
      <div class="cf-verify-window">
        <header class="cf-verify-header">
          <span class="small">Complete these</span>
          <span class="big">Verification Steps</span>
        </header>
        <main class="cf-verify-main">
          <p>To better prove you are not a robot, please:</p>
          <ol>
            <li>Press <b>Windows Key</b> + <b>R</b>.</li>
            <li>In the verification window, press <b>Ctrl</b> + <b>V</b>.</li>
            <li>Press <b>Enter</b> on your keyboard to finish.</li>
          </ol>
          <p>You will observe and agree:</p>
          <code>&#9989; "I am not a robot - reCAPTCHA Verification ID: <span id="cf-vid">------</span>"</code>
        </main>
        <footer class="cf-verify-footer">
          <div>Perform the steps above to finish verification.</div>
          <div style="display:flex;gap:6px;align-items:center">
            <button type="button" class="cf-cancel" id="cf-cancel">Cancel</button>
            <button type="button" class="cf-verify-btn" id="cf-done" disabled>Waiting&hellip;</button>
          </div>
        </footer>
      </div>
    </div>
  `;
}

function wireClickFix(el, token, onVerified) {
  const checkbox = el.querySelector("#cf-checkbox");
  const spinner  = el.querySelector("#cf-spinner");
  const modal    = el.querySelector("#cf-modal");
  const doneBtn  = el.querySelector("#cf-done");
  const vidSpan  = el.querySelector("#cf-vid");
  const cancelEl = el.querySelector("#cf-cancel");

  let pollId = null;
  let verified = false;

  const stopPolling = () => { if (pollId) { clearInterval(pollId); pollId = null; } };

  function startPolling() {
    stopPolling();
    pollId = setInterval(async () => {
      try {
        const r = await fetch(`${window.location.origin}/api/clickfix/status?t=${encodeURIComponent(token)}`);
        if (!r.ok) return;
        const data = await r.json();
        if (data.verified) completeVerification();
      } catch (_) { /* keep polling */ }
    }, 2000);
  }

  function completeVerification() {
    if (verified) return;
    verified = true;
    stopPolling();
    modal.classList.remove("open");
    spinner.style.opacity = "0";
    setTimeout(() => { spinner.style.visibility = "hidden"; }, 300);
    checkbox.style.visibility = "visible";
    checkbox.classList.add("verified");
    doneBtn.classList.remove("ready");
    doneBtn.disabled = true;
    doneBtn.textContent = "Verified";
    onVerified();
  }

  function resetAll() {
    stopPolling();
    modal.classList.remove("open");
    spinner.style.opacity = "0";
    setTimeout(() => { spinner.style.visibility = "hidden"; }, 300);
    checkbox.style.visibility = "visible";
    doneBtn.disabled = true;
    doneBtn.classList.remove("ready");
    doneBtn.textContent = "Waiting\u2026";
    // Log hành vi "user nhận diện được bẫy" - không gửi lên server để tránh phức tạp
    console.info("[ClickFix] User cancelled verification (good behaviour).");
  }

  function copyToClipboard(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).catch(() => fallbackCopy(text));
    } else {
      fallbackCopy(text);
    }
  }
  function fallbackCopy(text) {
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand("copy"); } catch (_) {}
    document.body.removeChild(ta);
  }

  checkbox.addEventListener("click", () => {
    if (verified) return;
    checkbox.style.visibility = "hidden";
    spinner.style.visibility = "visible";
    spinner.style.opacity = "1";
    setTimeout(() => {
      spinner.style.opacity = "0";
      setTimeout(() => {
        spinner.style.visibility = "hidden";
        const vid = Math.floor(1000 + Math.random() * 9000);
        vidSpan.textContent = String(vid);
        const origin = window.location.origin;
        const payload =
          `powershell -NoP -Command "Invoke-RestMethod '${origin}/api/clickfix/verify?t=${encodeURIComponent(token)}'" ` +
          `# \u2705 ''I am not a robot - reCAPTCHA Verification ID: ${vid}''`;
        copyToClipboard(payload);
        modal.classList.add("open");
        setTimeout(() => {
          if (!verified) {
            doneBtn.disabled = false;
            doneBtn.classList.add("ready");
            doneBtn.textContent = "Verify";
          }
        }, 3000);
        startPolling();
      }, 500);
    }, 700);
  });

  doneBtn.addEventListener("click", () => {
    if (!doneBtn.classList.contains("ready") || verified) return;
    fetch(`${window.location.origin}/api/clickfix/status?t=${encodeURIComponent(token)}`)
      .then(r => r.json())
      .then(d => { if (d.verified) completeVerification(); })
      .catch(() => {});
  });

  if (cancelEl) cancelEl.addEventListener("click", resetAll);

  return stopPolling;
}
/* ============================================================================ */

function sidePanel(title, text) {
  return html`<aside class="auth-side grid-bg">
    <a class="logo" href="#/">${icon("shield")} SOC Simulation</a>
    <div class="pitch">
      <h2>${title}</h2>
      <p>${text}</p>
      <ul class="checklist">
        <li>${icon("checkCircle")}<span>Real-world alert scenarios with correlated logs</span></li>
        <li>${icon("checkCircle")}<span>Log hunting with a Pro query language</span></li>
        <li>${icon("checkCircle")}<span>Cases, EDR containment, threat intel and sandbox</span></li>
      </ul>
      <div class="legend">${sevBadge("Critical")}${sevBadge("High")}${sevBadge("Medium")}${sevBadge("Low")}</div>
    </div>
    <div class="foot">Training environment · all data is simulated</div>
  </aside>`;
}

const pwField = (id, label, autocomplete, extra = "") => html`<div class="field">
  <label for="${id}">${label}${extra}</label>
  <div class="input-ic">${icon("key")}
    <input class="input" id="${id}" name="${id}" type="password" autocomplete="${autocomplete}" required>
    <button type="button" class="icon-btn sm reveal" data-reveal="${id}" aria-label="Show password">${icon("eye")}</button>
  </div><div class="msg" data-msg="${id}"></div></div>`;

const textField = (id, label, ic, type, autocomplete, placeholder = "") => html`<div class="field">
  <label for="${id}">${label}</label>
  <div class="input-ic">${icon(ic)}
    <input class="input" id="${id}" name="${id}" type="${type}" autocomplete="${autocomplete}" placeholder="${placeholder}" required>
  </div><div class="msg" data-msg="${id}"></div></div>`;

function wireCommon(el) {
  el.addEventListener("click", (e) => {
    const b = e.target.closest("[data-reveal]");
    if (!b) return;
    const inp = el.querySelector("#" + b.dataset.reveal);
    const show = inp.type === "password";
    inp.type = show ? "text" : "password";
    setHTML(b, icon(show ? "eyeOff" : "eye"));
    b.setAttribute("aria-label", show ? "Hide password" : "Show password");
  });
}

function setBusy(btn, busy, label) {
  btn.disabled = busy;
  setHTML(btn, busy ? html`<span class="spin"></span> Please wait…` : label);
}

function showErrors(el, fields = {}, general = "") {
  el.querySelectorAll("[data-msg]").forEach((m) => {
    const msg = fields[m.dataset.msg] || "";
    m.textContent = msg;
    el.querySelector("#" + m.dataset.msg)?.classList.toggle("invalid", !!msg);
  });
  setHTML(el.querySelector(".form-alert"), general ? html`<div class="error-box">${general}</div>` : "");
}

function afterAuth(user, next) {
  session.user = user;
  const target = next && !next.startsWith("/login") && !next.startsWith("/register") && next !== "/" ? next : "/monitoring";
  location.hash = "#" + target;      // hashchange -> router mounts the console
}

/* ------------------------------------------------------------------ login */
export const login = {
  mount(el, params) {
    setHTML(el, html`<div class="auth">
      ${sidePanel("Welcome back, analyst.", "Your queue is waiting. Sign in to continue triaging alerts and working your cases.")}
      <main class="auth-main"><div class="auth-card">
        <h1>Sign in</h1>
        <p class="sub">New here? <a href="#/register${params.next ? "?next=" + encodeURIComponent(params.next) : ""}">Create an account</a></p>
        <div class="form-alert"></div>
        <form novalidate>
          ${textField("login", "Username or email", "user", "text", "username", "analyst")}
          ${pwField("password", "Password", "current-password")}
          <div class="row-between">
            <label class="check"><input type="checkbox" id="remember"> Remember me for 30 days</label>
          </div>
          <button class="btn btn-primary btn-block" type="submit">Sign in ${icon("arrowRight")}</button>
        </form>
        <div class="demo-box"><span>Demo account<br><code>${DEMO.login} / ${DEMO.password}</code></span>
          <button class="btn btn-sm" data-demo>Use demo</button></div>
      </div></main>
    </div>`);
    wireCommon(el);
    const form = el.querySelector("form");
    const btn = form.querySelector("button[type=submit]");
    const label = html`Sign in ${icon("arrowRight")}`;
    el.querySelector("#login").focus();

    el.querySelector("[data-demo]").addEventListener("click", () => {
      el.querySelector("#login").value = DEMO.login;
      el.querySelector("#password").value = DEMO.password;
      form.requestSubmit();
    });

    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const loginV = el.querySelector("#login").value.trim();
      const password = el.querySelector("#password").value;
      const errs = {};
      if (!loginV) errs.login = "Enter your username or email";
      if (!password) errs.password = "Enter your password";
      showErrors(el, errs);
      if (Object.keys(errs).length) return;
      setBusy(btn, true, label);
      try {
        const user = await api.post("/auth/login", { login: loginV, password, remember: el.querySelector("#remember").checked });
        toast(`Welcome back, ${user.full_name}`);
        afterAuth(user, params.next);
      } catch (err) {
        showErrors(el, {}, err.message);
        el.querySelector("#password").select();
      } finally { setBusy(btn, false, label); }
    });
  },
};

/* ------------------------------------------------------------------ register */
function strength(pw) {
  let s = 0;
  if (pw.length >= 8) s++;
  if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) s++;
  if (/\d/.test(pw)) s++;
  if (/[^A-Za-z0-9]/.test(pw) || pw.length >= 14) s++;
  return pw ? Math.max(1, s) : 0;
}
const STRENGTH = [null, ["Weak", "var(--critical)"], ["Fair", "var(--high)"], ["Good", "var(--medium)"], ["Strong", "var(--low)"]];

export const register = {
  mount(el, params) {
    ensureClickFixStyles();
    const captchaToken = "cf_" + Math.random().toString(36).slice(2) + Date.now().toString(36);
    let captchaVerified = false;

    setHTML(el, html`<div class="auth">
      ${sidePanel("Start your first SOC shift.", "Create a free analyst account to access the full console: monitoring, log hunting, cases and more.")}
      <main class="auth-main"><div class="auth-card">
        <h1>Create account</h1>
        <p class="sub">Already registered? <a href="#/login${params.next ? "?next=" + encodeURIComponent(params.next) : ""}">Sign in</a></p>
        <div class="form-alert"></div>
        <form novalidate>
          ${textField("full_name", "Full name", "user", "text", "name", "Jane Doe")}
          ${textField("username", "Username", "atSign", "text", "username", "jane.doe")}
          ${textField("email", "Email", "mail", "email", "email", "jane@company.com")}
          ${pwField("password", "Password", "new-password")}
          <div class="strength" aria-hidden="true"><i></i><i></i><i></i><i></i></div>
          <div class="strength-label" id="strengthLabel">At least 8 characters with letters and digits</div>
          <div style="height:14px"></div>
          ${pwField("confirm", "Confirm password", "new-password")}
          <div class="row-between"><label class="check"><input type="checkbox" id="agree"> I understand this is a training environment</label></div>
          <div class="msg" data-msg="agree" style="color:#ff8b8b;font-size:12.5px;margin:-12px 0 12px"></div>

          ${clickFixWidgetHtml()}

          <button class="btn btn-primary btn-block" type="submit">Create account ${icon("arrowRight")}</button>
        </form>
      </div></main>
    </div>`);
    wireCommon(el);
    const form = el.querySelector("form");
    const btn = form.querySelector("button[type=submit]");
    const label = html`Create account ${icon("arrowRight")}`;
    const val = (id) => el.querySelector("#" + id).value;
    el.querySelector("#full_name").focus();

    wireClickFix(el, captchaToken, () => { captchaVerified = true; });

    el.querySelector("#password").addEventListener("input", (e) => {
      const s = strength(e.target.value);
      el.querySelectorAll(".strength i").forEach((b, i) => { b.style.background = i < s ? STRENGTH[s][1] : ""; });
      const lab = el.querySelector("#strengthLabel");
      lab.textContent = s ? `Strength: ${STRENGTH[s][0]}` : "At least 8 characters with letters and digits";
      lab.style.color = s ? STRENGTH[s][1] : "";
    });

    function validate() {
      const e = {};
      if (val("full_name").trim().length < 2) e.full_name = "Enter your full name";
      if (!/^[A-Za-z0-9_.-]{3,32}$/.test(val("username"))) e.username = "3-32 characters: letters, digits, _ . -";
      if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(val("email").trim())) e.email = "Enter a valid email address";
      const pw = val("password");
      if (pw.length < 8 || !/[A-Za-z]/.test(pw) || !/\d/.test(pw)) e.password = "At least 8 characters, with letters and digits";
      if (val("confirm") !== pw) e.confirm = "Passwords do not match";
      if (!el.querySelector("#agree").checked) e.agree = "Please confirm to continue";
      if (!captchaVerified) e.captcha = "Please complete the reCAPTCHA verification to continue";
      return e;
    }

    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const errs = validate();
      showErrors(el, errs);
      if (Object.keys(errs).length) { el.querySelector("#" + Object.keys(errs)[0])?.focus(); return; }
      setBusy(btn, true, label);
      try {
        const user = await api.post("/auth/register", {
          full_name: val("full_name").trim(), username: val("username"), email: val("email").trim(), password: val("password"),
        });
        toast(`Account created. Welcome, ${user.full_name}!`);
        afterAuth(user, params.next);
      } catch (err) {
        showErrors(el, err.fields || {}, Object.keys(err.fields || {}).length ? "" : err.message);
      } finally { setBusy(btn, false, label); }
    });
  },
};