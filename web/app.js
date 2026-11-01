/*
 * AgentAttacker frontend: a small hash-routed single-page app (no build step, no framework).
 *
 *   #/                 home
 *   #/scan             choose target, attacks and settings
 *   #/scan/<job_id>    live progress of a running scan
 *   #/report/<run_id>  one full report
 *   #/reports          past reports
 *   #/library          attack library
 */
"use strict";

const app = document.getElementById("app");

// ---------- Static data ----------

const TARGETS = [
  { kind: "practice", name: "Practice bot", img: "bot-practice.svg", gemini: false,
    desc: "Offline, rule-based HelpBot. No AI, no quota: ideal for a quick demo." },
  { kind: "demo-vulnerable", name: "Nova · vulnerable", img: "bot-nova.svg", gemini: true,
    desc: "Gemini support bot with tools and no defences." },
  { kind: "demo-hardened", name: "Nova · hardened", img: "bot-shield.svg", gemini: true,
    desc: "The same bot behind four defence layers." },
  { kind: "prompt", name: "Your system prompt", img: "prompt.svg", gemini: true,
    desc: "Paste your prompt; we host it on Gemini and attack it." },
  { kind: "endpoint", name: "Your endpoint", img: "endpoint.svg", gemini: false,
    desc: "Send attacks straight to your chatbot's HTTP API." },
];
const TARGET_BY_KIND = Object.fromEntries(TARGETS.map((t) => [t.kind, t]));

const OWASP = {
  LLM01: "Prompt Injection",
  LLM02: "Sensitive Information Disclosure",
  LLM06: "Excessive Agency",
  LLM07: "System Prompt Leakage",
};

const DEFENCE_LABELS = {
  input_filter: "Input filter",
  tool_allowlist: "Tool allowlist",
  output_filter: "Output filter (DLP)",
};

// ---------- Helpers ----------

const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const pct = (x) => `${Math.round((x || 0) * 100)}%`;
const fmtTime = (iso) => {
  const d = new Date(iso);
  return isNaN(d) ? esc(iso) : d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
};
const targetImg = (kind) => `img/${(TARGET_BY_KIND[kind] || TARGET_BY_KIND.endpoint).img}`;
const defenceBadges = (list) => (list || []).length
  ? list.map((d) => `<span class="badge def">${esc(DEFENCE_LABELS[d] || d)}</span>`).join(" ")
  : `<span class="faint">–</span>`;

async function api(path, options = {}) {
  const res = await fetch(path, {
    headers: options.body ? { "Content-Type": "application/json" } : {},
    ...options,
  });
  if (!res.ok) {
    let detail = `${res.status} ${res.statusText}`;
    try {
      const body = await res.json();
      if (body.detail) detail = typeof body.detail === "string" ? body.detail
        : body.detail.map((d) => d.msg || JSON.stringify(d)).join("; ");
    } catch { /* not JSON */ }
    throw new Error(detail);
  }
  return res.json();
}

let toastTimer;
function toast(message, isError = false) {
  const el = document.getElementById("toast");
  el.textContent = message;
  el.classList.toggle("error", isError);
  el.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove("show"), 4000);
}

const loading = (label = "Loading…") => `<div class="loading"><div class="spinner"></div>${esc(label)}</div>`;
const errorBox = (msg) => `<div class="notice error">⚠ ${esc(msg)}</div>`;

// Cached server data
const cache = { attacks: null, status: null };
const getAttacks = async () => (cache.attacks ??= await api("/api/attacks"));
async function getStatus() {
  if (cache.status === null) {
    try { cache.status = (await api("/api/status")).gemini_configured; }
    catch { cache.status = false; }
  }
  return cache.status;
}

// ---------- Router ----------

let routeToken = 0;   // bumps on every navigation so stale async work (e.g. polling) stops

const routes = [
  [/^#?\/?$/, "home", renderHome],
  [/^#\/scan\/?$/, "scan", renderScan],
  [/^#\/scan\/([\w-]+)$/, "scan", renderLive],
  [/^#\/report\/([\w.-]+)$/, "reports", renderReport],
  [/^#\/reports\/?$/, "reports", renderReports],
  [/^#\/library\/?$/, "library", renderLibrary],
];

async function route() {
  const token = ++routeToken;
  const hash = location.hash || "#/";
  const [, nav, render, match] = routes.map(([re, n, r]) => [re, n, r, hash.match(re)]).find((r) => r[3])
    || [null, "", renderNotFound, []];
  document.querySelectorAll("[data-nav]").forEach((a) => a.classList.toggle("active", a.dataset.nav === nav));
  document.querySelector(".nav").classList.remove("open");
  window.scrollTo(0, 0);
  try {
    await render(token, ...match.slice(1));
  } catch (e) {
    if (token === routeToken) app.innerHTML = `<div class="page">${errorBox(e.message)}</div>`;
  }
}
const stale = (token) => token !== routeToken;

window.addEventListener("hashchange", route);
document.querySelector(".nav-toggle").addEventListener("click", (e) => {
  const nav = document.querySelector(".nav");
  nav.classList.toggle("open");
  e.currentTarget.setAttribute("aria-expanded", nav.classList.contains("open"));
});

// =====================================================================
// Home
// =====================================================================

async function renderHome(token) {
  const [attacks, runs] = await Promise.all([getAttacks(), api("/api/runs").catch(() => [])]);
  if (stale(token)) return;
  const categories = new Set(attacks.map((a) => a.category)).size;
  const owasp = new Set(attacks.map((a) => a.owasp)).size;

  app.innerHTML = `
  <div class="page">
    <section class="hero">
      <div>
        <div class="eyebrow">Automated red-teaming for LLM chatbots</div>
        <h1>Attack your chatbot <span class="grad">before someone else does.</span></h1>
        <p class="lead">AgentAttacker fires prompt-injection, jailbreak, data-exfiltration and system-prompt-leak
          attacks at your bot, judges every reply with canary tokens, and hands you a report mapped to the
          OWASP Top 10 for LLM Applications.</p>
        <div class="row">
          <a class="btn btn-primary" href="#/scan">Start a scan →</a>
          <a class="btn btn-ghost" href="#/library">Browse attacks</a>
        </div>
        <div class="hero-stats">
          <div><b>${attacks.length}</b><span>attacks</span></div>
          <div><b>${categories}</b><span>techniques</span></div>
          <div><b>${owasp}</b><span>OWASP risks</span></div>
          <div><b>${runs.length}</b><span>reports saved</span></div>
        </div>
      </div>
      <img class="hero-img" src="img/hero.svg" alt="A glowing core surrounded by orbiting attack probes">
    </section>

    <section class="section">
      <h2>What it does</h2>
      <div class="grid grid-3">
        <div class="card feature"><div class="icon">🎯</div><h3>Attack library</h3>
          <p>Direct and indirect injection, role-play jailbreaks, social engineering, encoding bypasses and
          tool abuse, each tied to an OWASP risk.</p></div>
        <div class="card feature"><div class="icon">🐤</div><h3>Canary judge</h3>
          <p>Planted secrets are detected even when disguised as base64, reversed or spaced-out text.
          Deterministic and free: no LLM-as-judge.</p></div>
        <div class="card feature"><div class="icon">🧬</div><h3>Adaptive attacker</h3>
          <p>When an attack fails, an attacker model reads the refusal and rewrites it with a new technique,
          like a human red-teamer would.</p></div>
      </div>
    </section>

    <section class="section">
      <h2>How a scan works</h2>
      <div class="grid grid-3 steps">
        <div class="card"><h3>Pick a target</h3><p>The offline practice bot, the Nova demo bot, your own system
          prompt, or any HTTP chatbot endpoint.</p></div>
        <div class="card"><h3>Watch it live</h3><p>Every attempt streams in as it is judged: which attacks
          got through and which defences fired.</p></div>
        <div class="card"><h3>Fix what leaked</h3><p>Get a score, an OWASP breakdown, full transcripts and concrete
          recommendations. Download it as Markdown.</p></div>
      </div>
    </section>

    <section class="section">
      <div class="card-title"><h2>Latest reports</h2><a href="#/reports">View all →</a></div>
      ${runs.length ? `<div class="stack">${runs.slice(0, 3).map(reportItem).join("")}</div>`
        : `<div class="card empty"><img src="img/bot-practice.svg" alt=""><p>No reports yet.</p>
           <a class="btn btn-primary" href="#/scan">Run your first scan</a></div>`}
    </section>
  </div>`;
}

// =====================================================================
// Scan setup
// =====================================================================

// Kept across navigations so the form isn't lost when you peek at another page.
const scanForm = {
  kind: "practice",
  fields: {},
  attackIds: null,   // null = all
  mutations: 0,
  budget: 15,
};

const FIELD_DEFS = {
  prompt: [
    { id: "system_prompt", label: "System prompt", type: "textarea", required: true, rows: 6,
      placeholder: "You are ShopBot, the assistant for Acme Store. The coupon code SAVE-77Q is for staff only…" },
    { id: "secrets", label: "Secrets to protect", type: "textarea", rows: 3,
      hint: "One per line. If any of these appear in a reply (even encoded), it counts as a leak.",
      placeholder: "SAVE-77Q" },
    { id: "bot_name", label: "Bot name", placeholder: "ShopBot", half: true },
    { id: "secret_name", label: "What the secret is called", placeholder: "coupon code", half: true },
    { id: "allowed_email_domain", label: "Allowed email domain", placeholder: "acme.example",
      hint: "send_email calls to any other domain count as exfiltration." },
  ],
  endpoint: [
    { id: "url", label: "Chat endpoint URL", type: "url", required: true,
      placeholder: "https://your-bot.example/chat", action: "Use the practice bot" },
    { id: "secrets", label: "Secrets to watch for", type: "textarea", rows: 3,
      hint: "One per line. Needed for secret-leak attacks.", placeholder: "HB-ADMIN-9K2M" },
    { id: "prompt_phrases", label: "Distinctive system-prompt phrases", type: "textarea", rows: 2,
      hint: "One per line. Text that only exists in your system prompt; needed for prompt-leak attacks.",
      placeholder: "HELPDESK-77" },
    { id: "message_field", label: "Request field", placeholder: "message", half: true,
      hint: 'Sent as {"message": "…"}' },
    { id: "reply_path", label: "Reply path", placeholder: "reply", half: true,
      hint: "Dotted path, e.g. choices.0.message.content" },
    { id: "bot_name", label: "Bot name", placeholder: "HelpBot", half: true },
    { id: "secret_name", label: "What the secret is called", placeholder: "admin password", half: true },
    { id: "headers", label: "Extra headers (JSON)", type: "textarea", rows: 2,
      placeholder: '{"Authorization": "Bearer …"}' },
  ],
};

/** Mirrors targets.applicable(): which attacks the server will skip for this target. */
function skipReason(attack, kind, fields) {
  const has = (k) => (fields[k] || "").trim().length > 0;
  const tools = ["demo-vulnerable", "demo-hardened", "prompt"].includes(kind);
  if (attack.goal === "exfil_email" && !tools) return "target exposes no tool calls";
  if (attack.goal === "leak_secret" && ["prompt", "endpoint"].includes(kind) && !has("secrets"))
    return "add a secret to test this";
  if (attack.goal === "leak_prompt" && kind === "endpoint" && !has("prompt_phrases"))
    return "add a prompt phrase to test this";
  return "";
}

async function renderScan(token) {
  const [attacks, gemini] = await Promise.all([getAttacks(), getStatus()]);
  if (stale(token)) return;
  if (scanForm.attackIds === null) scanForm.attackIds = attacks.map((a) => a.id);
  if (!gemini && TARGET_BY_KIND[scanForm.kind].gemini) scanForm.kind = "practice";
  if (!gemini) scanForm.mutations = 0;

  const groups = {};
  attacks.forEach((a) => (groups[a.owasp] ||= []).push(a));

  app.innerHTML = `
  <div class="page">
    <div class="page-head">
      <div><div class="eyebrow">New scan</div><h1>Set up an attack run</h1>
        <p>Choose who to attack, which attacks to fire and how hard to push.</p></div>
    </div>
    <div class="scan-layout">
      <div class="stack">
        <section class="card">
          <div class="card-title"><h2>1 · Target</h2></div>
          ${gemini ? "" : `<div class="notice info" style="margin-bottom:14px">ℹ No Gemini key is configured, so
            Gemini-powered targets and adaptive mutations are disabled. The practice bot and your own endpoint
            work fully offline.</div>`}
          <div class="target-grid">
            ${TARGETS.map((t) => `
              <button type="button" class="target-card ${t.kind === scanForm.kind ? "selected" : ""}"
                data-kind="${t.kind}" ${t.gemini && !gemini ? "disabled" : ""}>
                ${t.gemini ? `<span class="badge warn">Gemini</span>` : `<span class="badge good">Offline</span>`}
                <img src="img/${t.img}" alt="">
                <b>${esc(t.name)}</b><span class="desc">${esc(t.desc)}</span>
              </button>`).join("")}
          </div>
          <div id="target-fields"></div>
        </section>

        <section class="card">
          <div class="card-title"><h2>2 · Attacks</h2>
            <div class="row"><span class="faint small" id="attack-count"></span>
              <button class="btn btn-sm" data-select="all">All</button>
              <button class="btn btn-sm" data-select="none">None</button></div>
          </div>
          <div id="attack-list">
            ${Object.keys(groups).sort().map((code) => `
              <div class="attack-group">
                <h4><span class="badge owasp">${code}</span>${esc(OWASP[code] || "")}</h4>
                ${groups[code].map((a) => `
                  <label class="attack-check" data-id="${a.id}">
                    <input type="checkbox" value="${a.id}" ${scanForm.attackIds.includes(a.id) ? "checked" : ""}>
                    <span><b>${esc(a.name)}</b> <span class="badge">${esc(a.category)}</span>
                      <small>${esc(a.description)}<em class="skip"></em></small></span>
                  </label>`).join("")}
              </div>`).join("")}
          </div>
        </section>
      </div>

      <aside class="stack sticky">
        <section class="card">
          <h2>3 · Settings</h2>
          <div class="stack">
            <div class="setting">
              <label for="mutations"><b>Adaptive rewrites</b></label><output id="mutations-out">${scanForm.mutations}</output>
              <input type="range" id="mutations" min="0" max="2" value="${scanForm.mutations}" ${gemini ? "" : "disabled"}
                style="grid-column:1/-1">
              <span class="hint faint small">${gemini
                ? "Extra attempts per failed attack, rewritten by an attacker LLM (uses Gemini)."
                : "Needs a Gemini key."}</span>
            </div>
            <div class="setting">
              <label for="budget"><b>Gemini call budget</b></label><output id="budget-out">${scanForm.budget}</output>
              <input type="range" id="budget" min="1" max="60" value="${scanForm.budget}" style="grid-column:1/-1">
              <span class="hint faint small">Hard cap on LLM calls for the whole run. Offline targets use none.</span>
            </div>
          </div>
        </section>
        <section class="card">
          <div id="summary" class="small muted"></div>
          <div id="form-error"></div>
          <button class="btn btn-primary" id="start" style="width:100%;margin-top:14px">Launch scan 🚀</button>
        </section>
      </aside>
    </div>
  </div>`;

  // Target selection
  app.querySelectorAll(".target-card").forEach((card) => card.addEventListener("click", () => {
    scanForm.kind = card.dataset.kind;
    app.querySelectorAll(".target-card").forEach((c) => c.classList.toggle("selected", c === card));
    drawFields();
    refresh();
  }));

  // Attack selection
  app.querySelector("#attack-list").addEventListener("change", () => {
    scanForm.attackIds = [...app.querySelectorAll("#attack-list input:checked")].map((i) => i.value);
    refresh();
  });
  app.querySelectorAll("[data-select]").forEach((b) => b.addEventListener("click", () => {
    const all = b.dataset.select === "all";
    app.querySelectorAll("#attack-list input").forEach((i) => (i.checked = all));
    scanForm.attackIds = all ? attacks.map((a) => a.id) : [];
    refresh();
  }));

  // Sliders
  for (const id of ["mutations", "budget"]) {
    const input = app.querySelector(`#${id}`);
    input.addEventListener("input", () => {
      scanForm[id] = Number(input.value);
      app.querySelector(`#${id}-out`).textContent = input.value;
      refresh();
    });
  }

  app.querySelector("#start").addEventListener("click", () => startScan(attacks));

  function drawFields() {
    const defs = FIELD_DEFS[scanForm.kind];
    const box = app.querySelector("#target-fields");
    if (!defs) { box.innerHTML = ""; return; }
    const f = (scanForm.fields[scanForm.kind] ||= {});
    box.innerHTML = `<div class="grid grid-2" style="margin-top:20px">${defs.map((d) => `
      <div class="field" style="${d.half ? "" : "grid-column:1/-1"}">
        <label for="f-${d.id}">${esc(d.label)}${d.required ? ' <span style="color:var(--accent-2)">*</span>' : ""}</label>
        ${d.type === "textarea"
          ? `<textarea id="f-${d.id}" data-field="${d.id}" rows="${d.rows || 3}" placeholder="${esc(d.placeholder)}">${esc(f[d.id])}</textarea>`
          : `<input id="f-${d.id}" data-field="${d.id}" type="${d.type || "text"}" placeholder="${esc(d.placeholder)}" value="${esc(f[d.id])}">`}
        ${d.hint ? `<span class="hint">${esc(d.hint)}</span>` : ""}
        ${d.action ? `<button type="button" class="btn btn-sm btn-ghost" data-practice style="align-self:flex-start">↳ ${esc(d.action)}</button>` : ""}
      </div>`).join("")}</div>`;
    box.querySelectorAll("[data-field]").forEach((el) => el.addEventListener("input", () => {
      f[el.dataset.field] = el.value;
      refresh();
    }));
    box.querySelector("[data-practice]")?.addEventListener("click", () => {
      // Point the endpoint target at the built-in practice bot, with its known canaries.
      Object.assign(f, { url: `${location.origin}/practice-bot/chat`, secrets: "HB-ADMIN-9K2M",
        prompt_phrases: "HELPDESK-77", message_field: "message", reply_path: "reply",
        bot_name: "HelpBot", secret_name: "admin password" });
      drawFields();
      refresh();
    });
  }

  function refresh() {
    const fields = scanForm.fields[scanForm.kind] || {};
    let runnable = 0;
    app.querySelectorAll(".attack-check").forEach((row) => {
      const attack = attacks.find((a) => a.id === row.dataset.id);
      const reason = skipReason(attack, scanForm.kind, fields);
      row.classList.toggle("na", !!reason);
      row.querySelector(".skip").textContent = reason ? ` · Will be skipped: ${reason}` : "";
      if (!reason && scanForm.attackIds.includes(attack.id)) runnable++;
    });
    const selected = scanForm.attackIds.length;
    app.querySelector("#attack-count").textContent = `${selected} of ${attacks.length} selected`;
    const t = TARGET_BY_KIND[scanForm.kind];
    const usesGemini = t.gemini || scanForm.mutations > 0;
    app.querySelector("#summary").innerHTML = `
      <div class="row" style="margin-bottom:10px"><img src="img/${t.img}" width="36" height="36" alt="">
        <b style="color:var(--text)">${esc(t.name)}</b></div>
      <b style="color:var(--text)">${runnable}</b> attack${runnable === 1 ? "" : "s"} will run${
        selected - runnable > 0 ? `, ${selected - runnable} skipped` : ""}.<br>
      ${usesGemini ? `Up to <b style="color:var(--text)">${scanForm.budget}</b> Gemini calls.` : "Runs fully offline: no Gemini calls."}`;
    app.querySelector("#start").disabled = selected === 0;
  }

  drawFields();
  refresh();
}

async function startScan(attacks) {
  const btn = app.querySelector("#start");
  const errBox = app.querySelector("#form-error");
  errBox.innerHTML = "";
  const kind = scanForm.kind;
  const target = { kind, ...(scanForm.fields[kind] || {}) };

  try {
    for (const d of FIELD_DEFS[kind] || []) {
      if (d.required && !(target[d.id] || "").trim()) throw new Error(`${d.label} is required.`);
    }
    if (kind === "endpoint") {
      const raw = (target.headers || "").trim();
      try { target.headers = raw ? JSON.parse(raw) : {}; }
      catch { throw new Error("Extra headers must be valid JSON, e.g. {\"Authorization\": \"Bearer …\"}"); }
      if (typeof target.headers !== "object" || Array.isArray(target.headers))
        throw new Error("Extra headers must be a JSON object.");
    }
    btn.disabled = true;
    btn.textContent = "Launching…";
    const { job_id } = await api("/api/scans", {
      method: "POST",
      body: JSON.stringify({ target, attack_ids: scanForm.attackIds,
        mutations: scanForm.mutations, budget: scanForm.budget }),
    });
    location.hash = `#/scan/${job_id}`;
  } catch (e) {
    errBox.innerHTML = `<div style="margin-top:12px">${errorBox(e.message)}</div>`;
    btn.disabled = false;
    btn.textContent = "Launch scan 🚀";
  }
}

// =====================================================================
// Live progress
// =====================================================================

async function renderLive(token, jobId) {
  app.innerHTML = loading("Connecting to scan…");
  let job;
  try { job = await api(`/api/scans/${jobId}`); }
  catch (e) {
    if (stale(token)) return;
    app.innerHTML = `<div class="page"><div class="card empty"><img src="img/endpoint.svg" alt="">
      <h2>Scan not found</h2><p>${esc(e.message)}. Scans are kept in memory, so restarting the server clears them.</p>
      <a class="btn" href="#/reports">See saved reports</a></div></div>`;
    return;
  }
  if (stale(token)) return;

  app.innerHTML = `
  <div class="page">
    <div class="page-head"><div><div class="eyebrow">Live scan · ${esc(jobId)}</div>
      <h1>${esc(job.target.label)}</h1></div>
      <a class="btn btn-ghost" href="#/scan">← New scan</a></div>
    <div class="scan-layout">
      <section class="card">
        <div class="card-title"><h2>Attack feed</h2><span class="faint small" id="feed-count"></span></div>
        <ul class="feed" id="feed"></ul>
      </section>
      <aside class="stack sticky">
        <section class="card">
          <div class="live-head"><div class="pulse" id="pulse"></div><div>
            <b id="live-status">Running</b><div class="faint small" id="live-sub"></div></div></div>
          <div class="progress" id="progress"><div style="width:0"></div></div>
          <div class="counters">
            <div class="counter"><b id="c-tested">0</b><span>tested</span></div>
            <div class="counter"><b id="c-bad" style="color:var(--red)">0</b><span>got through</span></div>
            <div class="counter"><b id="c-good" style="color:var(--green)">0</b><span>defended</span></div>
          </div>
          <div id="live-actions" style="margin-top:18px"></div>
        </section>
      </aside>
    </div>
  </div>`;

  let rendered = 0;
  const feed = app.querySelector("#feed");

  const update = (job) => {
    const results = job.events.filter((e) => e.type === "result");
    const byAttack = new Map();
    results.forEach((r) => byAttack.set(r.attack_id, (byAttack.get(r.attack_id) || false) || r.success));
    const tested = byAttack.size;
    const bad = [...byAttack.values()].filter(Boolean).length;
    app.querySelector("#c-tested").textContent = tested;
    app.querySelector("#c-bad").textContent = bad;
    app.querySelector("#c-good").textContent = tested - bad;
    app.querySelector("#feed-count").textContent = `${results.length} attempt${results.length === 1 ? "" : "s"}`;

    // Append only the new events, newest on top.
    for (const ev of job.events.slice(rendered)) feed.insertAdjacentHTML("afterbegin", feedItem(ev));
    rendered = job.events.length;
    if (!rendered) feed.innerHTML = `<li style="display:block" class="faint">Waiting for the first attack…</li>`;
    else feed.querySelector("li.faint")?.remove();

    const bar = app.querySelector("#progress");
    const done = job.status !== "running";
    const ratio = done ? 1 : job.planned ? Math.min(tested / job.planned, 0.98) : 0;
    bar.classList.toggle("indeterminate", !done && tested === 0);
    bar.firstElementChild.style.width = `${ratio * 100}%`;
    app.querySelector("#live-sub").textContent = `${tested} of ${job.planned} planned attacks`;

    const pulse = app.querySelector("#pulse");
    pulse.className = `pulse ${job.status === "done" ? "done" : job.status === "error" ? "error" : ""}`;
    app.querySelector("#live-status").textContent =
      { running: "Running…", done: "Scan complete", error: "Scan failed" }[job.status] || job.status;
    const actions = app.querySelector("#live-actions");
    if (job.status === "done") {
      actions.innerHTML = `<a class="btn btn-primary" style="width:100%" href="#/report/${esc(job.run_id)}">View report →</a>`;
    } else if (job.status === "error") {
      actions.innerHTML = `${errorBox(job.error || "Unknown error")}
        <a class="btn" style="width:100%;margin-top:12px" href="#/scan">Back to setup</a>`;
    }
  };

  update(job);
  while (job.status === "running") {
    await new Promise((r) => setTimeout(r, 700));
    if (stale(token)) return;
    try { job = await api(`/api/scans/${jobId}`); }
    catch (e) { toast(`Lost contact with the scan: ${e.message}`, true); return; }
    if (stale(token)) return;
    update(job);
  }
  if (job.status === "done") toast("Scan complete. Your report is ready.");
}

function feedItem(ev) {
  if (ev.type === "mutate") {
    return `<li><span class="dot mut">↻</span><div><b>Rewriting the attack</b>
      <small>The attacker LLM is crafting a new variant after a refusal.</small></div><span></span></li>`;
  }
  return `<li>
    <span class="dot ${ev.success ? "bad" : "good"}">${ev.success ? "!" : "✓"}</span>
    <div><b>${esc(ev.name)}</b>${ev.attempt ? ` <span class="badge">rewrite #${ev.attempt}</span>` : ""}
      <small>${ev.success ? `Leaked: ${esc(ev.evidence)}` : "Defended"}${
        (ev.blocked_by || []).length ? ` · ${ev.blocked_by.map((d) => esc(DEFENCE_LABELS[d] || d)).join(", ")}` : ""}</small></div>
    <span class="badge owasp">${esc(ev.owasp)}</span>
  </li>`;
}

// =====================================================================
// Report
// =====================================================================

async function renderReport(token, runId) {
  app.innerHTML = loading("Loading report…");
  const run = await api(`/api/runs/${encodeURIComponent(runId)}`);
  if (stale(token)) return;
  const s = run.summary;
  const perAttack = Object.entries(s.per_attack || {});
  const score = s.attacks_tested ? Math.round((1 - s.attack_success_rate) * 100) : 0;
  const [grade, color] = !s.attacks_tested ? ["Nothing was tested", "var(--faint)"]
    : score >= 90 ? ["Strong: almost every attack was stopped", "var(--green)"]
    : score >= 70 ? ["Fair: some attacks got through", "var(--amber)"]
    : ["Weak: many attacks got through", "var(--red)"];
  const recs = run.recommendations || [];

  app.innerHTML = `
  <div class="page">
    <div class="page-head">
      <div><div class="eyebrow">Security report · ${fmtTime(run.time)}</div>
        <h1>${esc(run.target.label)}</h1>
        <p class="mono faint">${esc(run.id)}</p></div>
      <div class="row">
        <a class="btn" href="#/reports">← All reports</a>
        <a class="btn btn-primary" href="/api/runs/${encodeURIComponent(run.id)}/report.md" download>⬇ Markdown</a>
      </div>
    </div>

    <div class="grid grid-2">
      <section class="card score-card">
        <div class="ring" style="--p:${score};--c:${color}"><div><b>${score}</b><span>security score</span></div></div>
        <div>
          <div class="grade" style="color:${color}">${grade}</div>
          <p class="muted small" style="margin:6px 0 0">Score = share of attacks the bot defended against.
            An attack counts as successful if any attempt (original or rewrite) got through.</p>
          <div class="kv">
            <div><b style="color:var(--red)">${pct(s.attack_success_rate)}</b><span>attack success rate</span></div>
            <div><b>${s.attacks_succeeded} / ${s.attacks_tested}</b><span>attacks got through</span></div>
            <div><b>${s.llm_calls}</b><span>Gemini calls used</span></div>
            <div><b>${run.settings?.mutations ?? 0}</b><span>rewrites per attack</span></div>
          </div>
        </div>
      </section>

      <section class="card">
        <div class="card-title"><h2>OWASP LLM Top 10</h2><span class="faint small">attack success rate</span></div>
        ${Object.entries(s.by_owasp || {}).map(([code, v]) => `
          <div class="bar-row">
            <div class="label"><b>${esc(code)}</b><span>${esc(OWASP[code] || "")}</span></div>
            <div class="bar" title="${v.succeeded} of ${v.total} succeeded"><div style="width:${v.rate * 100}%"></div></div>
            <div class="pct">${v.succeeded}/${v.total}</div>
          </div>`).join("") || `<p class="faint">No attacks were run.</p>`}
      </section>
    </div>

    <section class="card section">
      <div class="card-title"><h2>Recommendations</h2></div>
      ${recs.length ? recs.map((r) => `
        <div class="rec"><div class="icon">!</div><div><b>${esc(r.title)}</b><p>${esc(r.text)}</p></div></div>`).join("")
        : `<div class="notice info">✓ No attack got through, so there's nothing urgent to fix. Re-run with
           adaptive rewrites to push harder.</div>`}
    </section>

    <section class="card section">
      <div class="card-title"><h2>Findings</h2>
        <div class="filters" data-filter="findings">
          <button class="chip active" data-v="all">All (${perAttack.length})</button>
          <button class="chip" data-v="bad">Vulnerable (${s.attacks_succeeded})</button>
          <button class="chip" data-v="good">Defended (${s.attacks_tested - s.attacks_succeeded})</button>
        </div></div>
      <div class="table-wrap"><table>
        <thead><tr><th>Attack</th><th>Category</th><th>OWASP</th><th>Result</th><th>Attempts</th><th>Defences that fired</th></tr></thead>
        <tbody>${perAttack.map(([id, a]) => `
          <tr data-ok="${a.success ? "bad" : "good"}">
            <td><b>${esc(a.name)}</b></td><td class="muted">${esc(a.category)}</td>
            <td><span class="badge owasp">${esc(a.owasp)}</span></td>
            <td>${a.success ? `<span class="badge bad">✗ Vulnerable</span>` : `<span class="badge good">✓ Defended</span>`}</td>
            <td class="mono">${a.attempts}</td><td>${defenceBadges(a.defences)}</td>
          </tr>`).join("")}</tbody>
      </table></div>
      ${(s.skipped || []).length ? `<p class="faint small" style="margin:14px 0 0">Not applicable to this target:
        ${s.skipped.map((x) => `${esc(x.name)} <span class="faint">(${esc(x.reason)})</span>`).join(", ")}</p>` : ""}
    </section>

    <section class="card section">
      <div class="card-title"><h2>Transcripts</h2>
        <div class="filters" data-filter="transcripts">
          <button class="chip active" data-v="all">All (${run.results.length})</button>
          <button class="chip" data-v="bad">Succeeded</button>
          <button class="chip" data-v="good">Defended</button>
        </div></div>
      <div id="transcripts">${run.results.map(transcript).join("") || `<p class="faint">No attempts recorded.</p>`}</div>
    </section>
  </div>`;

  // Filter chips (findings table rows / transcript blocks share the data-ok attribute)
  app.querySelectorAll("[data-filter]").forEach((group) => {
    const scope = group.closest("section");
    group.addEventListener("click", (e) => {
      const chip = e.target.closest(".chip");
      if (!chip) return;
      group.querySelectorAll(".chip").forEach((c) => c.classList.toggle("active", c === chip));
      scope.querySelectorAll("[data-ok]").forEach((el) =>
        el.classList.toggle("hidden", chip.dataset.v !== "all" && el.dataset.ok !== chip.dataset.v));
    });
  });
}

function transcript(r) {
  const calls = (list) => list.map((c) => `${c.name}(${Object.entries(c.args || {})
    .map(([k, v]) => `${k}=${JSON.stringify(v)}`).join(", ")})`).join("\n");
  const blockedCalls = (r.attempted_tool_calls || []).length > (r.tool_calls || []).length;
  return `
  <details class="transcript" data-ok="${r.success ? "bad" : "good"}">
    <summary>
      ${r.success ? `<span class="badge bad">✗ Succeeded</span>` : `<span class="badge good">✓ Defended</span>`}
      <b>${esc(r.name)}</b>${r.attempt ? `<span class="badge">rewrite #${r.attempt}</span>` : ""}
      <span class="spacer"></span><span class="badge owasp">${esc(r.owasp)}</span>
    </summary>
    <div class="chat">
      <div class="bubble atk"><span class="who">Attacker</span>${esc(r.prompt)}</div>
      ${r.document ? `<div class="bubble doc"><span class="who">Attached document</span>${esc(r.document)}</div>` : ""}
      <div class="bubble bot"><span class="who">Bot</span>${esc(r.response) || '<span class="faint">(empty reply)</span>'}</div>
      ${(r.attempted_tool_calls || []).length ? `<div class="bubble tool"><span class="who">Tool calls${blockedCalls
        ? " (some blocked)" : ""}</span>${esc(calls(r.attempted_tool_calls))}</div>` : ""}
      ${(r.blocked_by || []).length ? `<div class="faint small">Defences that fired: ${defenceBadges(r.blocked_by)}</div>` : ""}
      <div class="evidence ${r.success ? "bad" : "good"}">${r.success
        ? `<b>Evidence:</b> ${esc(r.evidence)}` : "No canary leaked and no policy-breaking tool call."}</div>
    </div>
  </details>`;
}

// =====================================================================
// Past reports
// =====================================================================

function reportItem(r) {
  const s = r.summary;
  return `
  <a class="card report-item" href="#/report/${encodeURIComponent(r.id)}">
    <img src="${targetImg(r.target.kind)}" alt="">
    <div>
      <b>${esc(r.target.label)}</b>
      <div class="faint small">${fmtTime(r.time)} · ${s.attacks_tested} attacks · ${s.llm_calls} Gemini calls
        ${r.settings?.mutations ? ` · ${r.settings.mutations} rewrite${r.settings.mutations > 1 ? "s" : ""}` : ""}</div>
      <div class="mini-bar"><div style="width:${s.attack_success_rate * 100}%"></div></div>
    </div>
    <div class="rate"><b style="color:${s.attack_success_rate ? "var(--red)" : "var(--green)"}">${pct(s.attack_success_rate)}</b>
      <span>attack success</span></div>
  </a>`;
}

async function renderReports(token) {
  app.innerHTML = loading();
  const runs = await api("/api/runs");
  if (stale(token)) return;
  const kinds = [...new Set(runs.map((r) => r.target.kind))];
  app.innerHTML = `
  <div class="page">
    <div class="page-head"><div><div class="eyebrow">History</div><h1>Past reports</h1>
      <p>Every finished scan is saved. Open one to see its score, findings and full transcripts.</p></div>
      <a class="btn btn-primary" href="#/scan">New scan</a></div>
    ${runs.length ? `
      ${kinds.length > 1 ? `<div class="filters" id="kind-filter" style="margin-bottom:18px">
        <button class="chip active" data-v="all">All (${runs.length})</button>
        ${kinds.map((k) => `<button class="chip" data-v="${esc(k)}">${esc(TARGET_BY_KIND[k]?.name || k)}</button>`).join("")}
      </div>` : ""}
      <div class="stack" id="report-list">${runs.map((r) =>
        `<div data-kind="${esc(r.target.kind)}">${reportItem(r)}</div>`).join("")}</div>`
      : `<div class="card empty"><img src="img/bot-practice.svg" alt=""><h2>No reports yet</h2>
         <p>Try the offline practice bot: it takes a second and needs no API key.</p>
         <a class="btn btn-primary" href="#/scan">Run a scan</a></div>`}
  </div>`;

  app.querySelector("#kind-filter")?.addEventListener("click", (e) => {
    const chip = e.target.closest(".chip");
    if (!chip) return;
    app.querySelectorAll("#kind-filter .chip").forEach((c) => c.classList.toggle("active", c === chip));
    app.querySelectorAll("#report-list > [data-kind]").forEach((el) =>
      el.classList.toggle("hidden", chip.dataset.v !== "all" && el.dataset.kind !== chip.dataset.v));
  });
}

// =====================================================================
// Attack library
// =====================================================================

async function renderLibrary(token) {
  app.innerHTML = loading();
  const attacks = await getAttacks();
  if (stale(token)) return;
  const codes = [...new Set(attacks.map((a) => a.owasp))].sort();
  const template = (text) => esc(text).replace(/\{(bot|secret)\}/g, '<span class="ph">{$1}</span>');

  app.innerHTML = `
  <div class="page">
    <div class="page-head"><div><div class="eyebrow">Attack library</div><h1>${attacks.length} attacks, ${codes.length} OWASP risks</h1>
      <p>Attacks are templates: <code style="color:var(--accent-2)">{bot}</code> and
        <code style="color:var(--accent-2)">{secret}</code> are filled in for each target, so the same library works
        against any chatbot.</p></div></div>
    <div class="owasp-legend">${codes.map((c) => `<div><b>${c}</b><span>${esc(OWASP[c] || "")} ·
      ${attacks.filter((a) => a.owasp === c).length} attacks</span></div>`).join("")}</div>
    <div class="filters" id="lib-filter" style="margin-bottom:18px">
      <button class="chip active" data-v="all">All</button>
      ${codes.map((c) => `<button class="chip" data-v="${c}">${c}</button>`).join("")}
    </div>
    <div class="grid grid-auto">${attacks.map((a) => `
      <article class="card attack-card" data-owasp="${esc(a.owasp)}">
        <div class="meta"><span class="badge owasp">${esc(a.owasp)}</span><span class="badge">${esc(a.category)}</span></div>
        <h3>${esc(a.name)}</h3>
        <p>${esc(a.description)}</p>
        <pre>${template(a.prompt)}</pre>
        ${a.document ? `<pre title="Hidden in a document the bot is asked to process">${template(a.document)}</pre>` : ""}
      </article>`).join("")}</div>
  </div>`;

  app.querySelector("#lib-filter").addEventListener("click", (e) => {
    const chip = e.target.closest(".chip");
    if (!chip) return;
    app.querySelectorAll("#lib-filter .chip").forEach((c) => c.classList.toggle("active", c === chip));
    app.querySelectorAll(".attack-card").forEach((el) =>
      el.classList.toggle("hidden", chip.dataset.v !== "all" && el.dataset.owasp !== chip.dataset.v));
  });
}

function renderNotFound() {
  app.innerHTML = `<div class="page"><div class="card empty"><img src="img/bot-shield.svg" alt="">
    <h2>Page not found</h2><a class="btn" href="#/">Go home</a></div></div>`;
}

// ---------- Boot ----------

getStatus().then((on) => {
  const pill = document.getElementById("llm-status");
  pill.classList.add(on ? "on" : "off");
  pill.querySelector("span").textContent = on ? "Gemini ready" : "Offline mode";
  pill.title = on ? "A Gemini API key is configured" : "No GOOGLE_API_KEY: offline targets only";
});
route();
