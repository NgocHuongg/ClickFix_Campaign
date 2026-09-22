import { session } from "../api.js";
import { html, icon, setHTML, sevBadge } from "../utils.js";

const FEED = [
  ["Critical", "SOC343 - WinRAR Path Traversal (CVE-2025-8088)"],
  ["High", "SOC344 - EDR Tampering Attempt via EDR-Freeze"],
  ["Medium", "SOC331 - Phishing URL Clicked"],
  ["Critical", "SOC342 - SharePoint ToolShell Auth Bypass"],
  ["Low", "SOC325 - Port Scan from External IP"],
  ["High", "SOC337 - Lazarus Phishing Campaign (APT38)"],
  ["Medium", "SOC333 - RDP Brute Force Attempt"],
  ["Critical", "SOC328 - Ransomware Encryption Behavior"],
  ["High", "SOC332 - SQL Injection Attempt Detected"],
];

const FEATURES = [
  ["monitor", "Alert Monitoring", "Triage a live queue across Main, Investigation and Closed channels. Take ownership, escalate, and record a verdict."],
  ["list", "Log Management", "Hunt through thousands of events with point-and-click filters or a real query language with pipes and autocomplete."],
  ["clipboard", "Case Management", "Turn alerts into cases, document evidence in a timeline and track status until closure."],
  ["hdd", "Endpoint Security", "EDR view of every host: process tree, network activity, shell history and one-click containment."],
  ["shield", "Threat Intel", "Look up IPs, domains and hashes, then pivot straight into your own telemetry."],
  ["mail", "Email Security", "Inspect headers and attachments of phishing mail, quarantine or block with one click."],
  ["box", "Sandbox", "Read dynamic analysis reports with behaviour signatures and MITRE ATT&CK mapping."],
  ["target", "Realistic scenarios", "Alerts modelled on recent CVEs and APT tradecraft, backed by correlated logs you have to find."],
];

export function mount(el) {
  const authed = !!session.user;
  const primary = authed ? html`<a class="btn btn-primary" href="#/monitoring">Open console ${icon("arrowRight")}</a>`
    : html`<a class="btn btn-primary" href="#/register">Get started ${icon("arrowRight")}</a>`;

  setHTML(el, html`<div class="landing grid-bg">
    <header class="l-nav"><div class="inner">
      <a class="logo" href="#/">${icon("shield")} SOC Simulation</a>
      <nav class="links" aria-label="Sections">
        <a href="#features" data-scroll="features">Features</a>
        <a href="#how" data-scroll="how">How it works</a>
        <a href="#query" data-scroll="query">Query language</a>
      </nav>
      <div class="right">
        ${authed ? "" : html`<a class="btn btn-ghost" href="#/login">Sign in</a>`}
        ${primary}
      </div>
    </div></header>

    <section class="l-hero"><div class="inner">
      <div>
        <span class="eyebrow"><span class="dot"></span> Blue team training platform</span>
        <h1>Triage. Hunt. Respond.<br><span class="gradient-text">Like a real SOC analyst.</span></h1>
        <p class="lead">A hands-on Security Operations Center simulator. Work real-world alerts, dig through correlated
          logs, contain endpoints and close cases, all in one console.</p>
        <div class="ctas">
          ${authed ? html`<a class="btn btn-primary btn-lg" href="#/monitoring">Open console ${icon("arrowRight")}</a>`
            : html`<a class="btn btn-primary btn-lg" href="#/register">Create free account ${icon("arrowRight")}</a>
                   <a class="btn btn-lg" href="#/login">${icon("key")} Sign in</a>`}
        </div>
        <div class="trust">
          <div><b>20+</b>alert scenarios</div><div><b>3,900+</b>log events</div><div><b>7</b>SOC modules</div>
        </div>
      </div>
      <div class="console-mock" aria-hidden="true">
        <div class="bar"><i></i><i></i><i></i><span>soc-console · monitoring</span></div>
        <div class="mtabs"><b>MAIN CHANNEL</b><b>INVESTIGATION</b><b>CLOSED</b></div>
        <div class="feed" id="feed"></div>
      </div>
    </div></section>

    <div class="stats-band"><div class="l-section" style="padding-top:30px;padding-bottom:30px">
      <div class="s"><b>4</b><span>severity levels, from ${sevBadge("Low")} to ${sevBadge("Critical")}</span></div>
      <div class="s"><b>7</b><span>log sources: OS, network, proxy, DNS, web, firewall, auth</span></div>
      <div class="s"><b>15</b><span>simulated endpoints with EDR telemetry</span></div>
      <div class="s"><b>&lt;10 ms</b><span>typical query time across all events</span></div>
    </div></div>

    <section class="l-section" id="features">
      <span class="kicker">Features</span>
      <h2>Everything a SOC shift needs</h2>
      <p class="sub">The same modules you'd use in a real SOC, connected together so each finding leads to the next one.</p>
      <div class="feat-grid">${FEATURES.map(([ic, t, d]) => html`<div class="feat"><div class="ic">${icon(ic)}</div><h3>${t}</h3><p>${d}</p></div>`)}</div>
    </section>

    <section class="l-section" id="how">
      <span class="kicker">How it works</span>
      <h2>From alert to verdict in three steps</h2>
      <p class="sub">Each alert is backed by events hidden in the logs. Your job is to find them and decide.</p>
      <div class="steps">
        <div class="step"><h3>Triage</h3><p>Pick an alert from the Main Channel, sorted and colour-coded by severity. Take ownership to start.</p>
          <div>${sevBadge("Critical")}${sevBadge("High")}${sevBadge("Medium")}${sevBadge("Low")}</div></div>
        <div class="step"><h3>Investigate</h3><p>Pivot into logs, endpoint telemetry, threat intel, email and sandbox reports. Build a case timeline as you go.</p></div>
        <div class="step"><h3>Respond</h3><p>Contain hosts, quarantine mail, then close the alert as True or False Positive with your analyst notes.</p></div>
      </div>
    </section>

    <section class="l-section" id="query">
      <div class="query-show">
        <div>
          <span class="kicker">Query language</span>
          <h2>Hunt like a pro</h2>
          <p class="sub" style="margin-bottom:24px">Start with point-and-click filters, then switch to Pro mode for full boolean logic.</p>
          <ul class="checklist">
            <li>${icon("checkCircle")}<span><b>Operators:</b> <code class="mono">= != &gt; &lt; IN CONTAINS STARTSWITH</code>, and <code class="mono">*</code> wildcards</span></li>
            <li>${icon("checkCircle")}<span><b>Boolean logic</b> with AND / OR / NOT and parentheses</span></li>
            <li>${icon("checkCircle")}<span><b>Pipes:</b> <code class="mono">| sort</code> and <code class="mono">| head</code>, plus syntax highlighting and autocomplete</span></li>
            <li>${icon("checkCircle")}<span>Errors point to the exact position, and all queries are parameterised for safety</span></li>
          </ul>
        </div>
        <div class="code-card">
          <div class="head"><span>Pro query</span><span>3 events · 4.5 ms</span></div>
          <pre><span class="tk-field">process</span><span class="tk-op">=</span>*EDR-Freeze* <span class="tk-kw">OR</span>
<span class="tk-field">raw_log</span> <span class="tk-kw">CONTAINS</span> <span class="tk-str">"WerFaultSecure"</span>
<span class="tk-pipe">|</span> <span class="tk-cmd">sort</span> <span class="tk-field">timestamp</span> asc</pre>
          <div class="res">
            <div>17:03:28 | OS | EDR-Freeze_1.0.exe  ← powershell.exe</div>
            <div>17:03:28 | OS | WerFaultSecure.exe  ← EDR-Freeze_1.0.exe</div>
            <div>17:03:32 | OS | CreateRemoteThread → MsMpEng.exe</div>
          </div>
        </div>
      </div>
    </section>

    <div class="cta-band">
      <h2>Ready for your first shift?</h2>
      <p>Create an account and start working the queue in under a minute.</p>
      ${authed ? html`<a class="btn btn-primary btn-lg" href="#/monitoring">Open console ${icon("arrowRight")}</a>`
        : html`<a class="btn btn-primary btn-lg" href="#/register">Create free account ${icon("arrowRight")}</a>`}
    </div>

    <footer class="l-foot"><div class="inner">
      <span>© ${new Date().getFullYear()} SOC Simulation · Training environment, all data is simulated</span>
      <span>FastAPI · SQLite · Vanilla JS</span>
    </div></footer>
  </div>`);

  // smooth scroll without touching the hash router
  el.addEventListener("click", (e) => {
    const a = e.target.closest("[data-scroll]");
    if (!a) return;
    e.preventDefault();
    document.getElementById(a.dataset.scroll)?.scrollIntoView({ behavior: "smooth" });
  });

  // live alert feed
  const feed = el.querySelector("#feed");
  let i = 0;
  const clock = () => new Date(Date.now() + 3 * 3600e3).toISOString().slice(11, 19);
  const push = () => {
    const [sev, rule] = FEED[i++ % FEED.length];
    const row = document.createElement("div");
    row.className = "feed-row";
    setHTML(row, html`${sevBadge(sev)}<span class="rn">${rule}</span><span class="t">${clock()}</span>`);
    feed.prepend(row);
    while (feed.children.length > 7) feed.lastChild.remove();
  };
  for (let k = 0; k < 6; k++) push();
  const timer = setInterval(push, 2600);
  return () => clearInterval(timer);
}
