export const dashboardCss = `
:root { color-scheme: dark; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #0b1020; color: #edf2ff; }
* { box-sizing: border-box; }
body { margin: 0; min-height: 100vh; background: radial-gradient(circle at top left, #183251 0, #0b1020 42rem); }
button, input, textarea { font: inherit; }
button { border: 0; border-radius: .65rem; padding: .7rem 1rem; background: #64d7a0; color: #07150f; font-weight: 750; cursor: pointer; }
button.secondary { background: #1c2a42; color: #d8e4ff; border: 1px solid #33486b; }
button:disabled { opacity: .5; cursor: wait; }
input, textarea { width: 100%; color: #edf2ff; background: #0d1627; border: 1px solid #304364; border-radius: .55rem; padding: .7rem; }
textarea { min-height: 5rem; resize: vertical; }
code, pre { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
pre { overflow: auto; max-height: 24rem; padding: 1rem; background: #070b14; border: 1px solid #263653; border-radius: .65rem; white-space: pre-wrap; }
.shell { max-width: 1180px; margin: 0 auto; padding: 2rem 1.2rem 5rem; }
header { display: flex; align-items: flex-start; justify-content: space-between; gap: 1rem; margin-bottom: 1.5rem; }
.brand { display: flex; gap: .8rem; align-items: center; }
.rook { width: 2.7rem; height: 2.7rem; display: grid; place-items: center; border-radius: .75rem; background: #64d7a0; color: #07150f; font-size: 1.45rem; }
h1, h2, h3, p { margin-top: 0; }
h1 { margin-bottom: .2rem; font-size: 1.55rem; }
h2 { font-size: 1.05rem; color: #dce7ff; }
.muted { color: #91a4c5; }
.grid { display: grid; grid-template-columns: repeat(12, 1fr); gap: 1rem; }
.card { grid-column: span 12; background: rgba(15, 24, 42, .9); border: 1px solid #273a5b; border-radius: 1rem; padding: 1.15rem; box-shadow: 0 1rem 2.5rem rgba(0,0,0,.18); }
.summary { grid-column: span 4; }
.wide { grid-column: span 8; }
.metric { font-size: 2rem; font-weight: 800; letter-spacing: -.04em; }
.status { display: inline-flex; gap: .35rem; align-items: center; padding: .28rem .55rem; border-radius: 99px; background: #1c2a42; color: #bfd0ed; font-size: .78rem; font-weight: 700; text-transform: uppercase; }
.status.complete, .status.ok, .severity.low { background: #123a2b; color: #7aebb3; }
.status.partial, .severity.medium { background: #403315; color: #ffd879; }
.status.failed, .status.error, .severity.high, .severity.critical { background: #481f2a; color: #ff9bac; }
.actions { display: flex; flex-wrap: wrap; gap: .6rem; }
.notice { padding: .85rem; background: #172641; border-left: .25rem solid #64d7a0; border-radius: .5rem; }
.error { border-left-color: #ff7891; color: #ffc2cc; }
.queue { display: grid; gap: .7rem; }
.finding { display: grid; grid-template-columns: 7rem minmax(0, 1fr) auto; gap: 1rem; align-items: center; padding: .85rem 0; border-top: 1px solid #243653; }
.finding:first-child { border-top: 0; }
.finding h3 { margin-bottom: .3rem; font-size: .95rem; }
.finding p { margin-bottom: .25rem; font-size: .86rem; }
.severity { display: inline-block; width: fit-content; padding: .25rem .5rem; border-radius: .45rem; font-size: .72rem; font-weight: 800; text-transform: uppercase; }
.approval { border-top: 1px solid #2a3b59; padding-top: 1rem; margin-top: 1rem; }
.approval-grid { display: grid; grid-template-columns: 1fr 2fr; gap: .7rem; }
.hidden { display: none !important; }
footer { margin-top: 2rem; color: #7083a3; font-size: .8rem; }
@media (max-width: 800px) { .summary, .wide { grid-column: span 12; } .finding { grid-template-columns: 1fr; } header { flex-direction: column; } .approval-grid { grid-template-columns: 1fr; } }
`;

export const dashboardJs = `
const state = { snapshot: null, job: null };
const $ = (id) => document.getElementById(id);
function element(tag, attrs = {}, text = "") {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) node.setAttribute(key, value);
  if (text) node.textContent = text;
  return node;
}
async function api(path, options = {}) {
  const response = await fetch(path, { credentials: "same-origin", headers: { "content-type": "application/json", ...(options.headers || {}) }, ...options });
  const body = await response.json().catch(() => ({ error: "The service returned an unreadable response" }));
  if (!response.ok) throw new Error(body.error || "Request failed");
  return body;
}
function showMessage(message, failed = false) {
  const banner = $("message");
  banner.textContent = message;
  banner.className = failed ? "notice error" : "notice";
  banner.classList.remove("hidden");
}
function statusBadge(value) { return element("span", { class: "status " + String(value).toLowerCase() }, String(value)); }
function render() {
  const snapshot = state.snapshot;
  if (!snapshot) return;
  $("repo-name").textContent = snapshot.repository.name;
  $("repo-path").textContent = snapshot.repository.path;
  $("stacks").textContent = snapshot.repository.stacks.join(", ") || "No supported stack detected yet";
  $("onboard").classList.toggle("hidden", snapshot.repository.configured);
  $("configured").textContent = snapshot.repository.configured ? "Configured" : "Setup needed";
  const scan = snapshot.scan;
  $("coverage").replaceChildren(scan ? statusBadge(scan.coverage_status) : statusBadge("not scanned"));
  $("finding-count").textContent = String(scan?.summary?.total ?? 0);
  $("scan-time").textContent = scan ? new Date(scan.generated_at).toLocaleString() : "Run the first scan to create evidence";
  const queue = $("findings");
  queue.replaceChildren();
  if (!snapshot.findings.length) queue.append(element("p", { class: "muted" }, "No findings artifact is available yet."));
  for (const finding of snapshot.findings) {
    const row = element("article", { class: "finding" });
    row.append(element("span", { class: "severity " + finding.severity }, finding.severity));
    const detail = element("div");
    detail.append(element("h3", {}, finding.plain_summary));
    detail.append(element("p", { class: "muted" }, finding.file + ":" + finding.line + " · " + finding.scanner + " · " + (finding.priority || finding.policy_status || "review")));
    detail.append(element("p", {}, finding.remediation_hint));
    row.append(detail);
    const action = element("button", { class: "secondary", type: "button", "data-finding": finding.id }, "Prepare plan");
    action.addEventListener("click", () => preparePlan(finding.id, action));
    row.append(action);
    queue.append(row);
  }
  const approvals = $("approvals");
  approvals.replaceChildren();
  if (!snapshot.approvals.length) approvals.append(element("p", { class: "muted" }, "Prepared remediation proposals will appear here for exact review."));
  for (const item of snapshot.approvals) approvals.append(renderApproval(item));
}
function renderApproval(item) {
  const wrapper = element("article", { class: "approval" });
  wrapper.append(element("h3", {}, item.finding_id + (item.approved ? " · approved" : " · awaiting approval")));
  wrapper.append(element("p", {}, item.risk_explanation));
  wrapper.append(element("p", { class: "muted" }, item.behavior_impact));
  wrapper.append(element("pre", {}, item.patch));
  wrapper.append(element("p", { class: "muted" }, "Tests: " + item.test_plan.join(" · ")));
  if (!item.approved) {
    const form = element("div", { class: "approval-grid" });
    const name = element("input", { placeholder: "Approver name", maxlength: "100" });
    const reason = element("textarea", { placeholder: "Why this exact patch and test plan are approved", maxlength: "500" });
    const button = element("button", { type: "button" }, "Approve exact proposal");
    button.addEventListener("click", async () => {
      button.disabled = true;
      try {
        await api("/api/approve", { method: "POST", body: JSON.stringify({ finding_id: item.finding_id, proposal_digest: item.proposal_digest, approved_by: name.value, reason: reason.value }) });
        showMessage("Approval receipt recorded. RepoRook still has not modified application code.");
        await refresh();
      } catch (error) { showMessage(error.message, true); }
      finally { button.disabled = false; }
    });
    form.append(name, reason, button);
    wrapper.append(form);
  }
  return wrapper;
}
async function preparePlan(findingId, button) {
  button.disabled = true;
  try { await api("/api/plan", { method: "POST", body: JSON.stringify({ finding_id: findingId }) }); showMessage("Plan prepared. Fill in its exact proposal before approval."); await refresh(); }
  catch (error) { showMessage(error.message, true); }
  finally { button.disabled = false; }
}
async function refresh() { state.snapshot = await api("/api/status"); state.job = await api("/api/job"); render(); renderJob(); }
function renderJob() {
  const job = state.job;
  $("scan-button").disabled = job.status === "running";
  $("job").textContent = job.status === "running" ? "Scan running…" : job.message || "Ready";
  if (job.status === "running") setTimeout(async () => { try { await refresh(); } catch {} }, 1500);
}
async function authenticate() {
  const token = new URLSearchParams(location.hash.slice(1)).get("token");
  if (token) {
    history.replaceState(null, "", location.pathname);
    await api("/api/session", { method: "POST", body: JSON.stringify({ token }) });
  }
  await refresh();
}
$("onboard-button").addEventListener("click", async () => {
  try { await api("/api/onboard", { method: "POST", body: JSON.stringify({ confirmation: "initialize RepoRook" }) }); showMessage("RepoRook configuration created. Review the recommended scanners, then scan."); await refresh(); }
  catch (error) { showMessage(error.message, true); }
});
$("scan-button").addEventListener("click", async () => {
  try { state.job = await api("/api/scan", { method: "POST", body: "{}" }); renderJob(); showMessage("Scan started. The dashboard will update when deterministic evidence is ready."); }
  catch (error) { showMessage(error.message, true); }
});
authenticate().catch((error) => { showMessage(error.message + ". Reopen the private dashboard URL printed by reporook-service.", true); });
`;

export function dashboardHtml(): string {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>RepoRook Service</title><link rel="stylesheet" href="/assets/app.css"></head>
<body><main class="shell">
<header><div class="brand"><div class="rook" aria-hidden="true">♜</div><div><h1>RepoRook</h1><p class="muted">Security guidance in plain English, with approval before code changes.</p></div></div><div class="actions"><span id="job" class="muted">Connecting…</span><button id="scan-button" type="button">Run security scan</button></div></header>
<div id="message" class="notice hidden" role="status"></div>
<section id="onboard" class="card hidden"><h2>Finish setup</h2><p>RepoRook detected this project and can create a conservative configuration plus ignore its local evidence directory. It will not install system software or edit application code.</p><button id="onboard-button" type="button">Initialize RepoRook</button></section>
<section class="grid" aria-label="Repository summary">
  <article class="card wide"><h2 id="repo-name">Repository</h2><p id="repo-path" class="muted"></p><p><span id="configured" class="status"></span></p><p id="stacks"></p></article>
  <article class="card summary"><h2>Coverage</h2><div id="coverage"></div><p id="scan-time" class="muted"></p></article>
  <article class="card summary"><h2>Findings</h2><div id="finding-count" class="metric">0</div><p class="muted">Scanner evidence remains separate from agent reasoning.</p></article>
  <article class="card wide"><h2>Prioritized vulnerability queue</h2><div id="findings" class="queue"></div></article>
  <article class="card"><h2>Approval queue</h2><p class="muted">Approval binds a named person to the exact patch and test plan. The service records evidence only; it does not apply the patch.</p><div id="approvals"></div></article>
</section>
<footer>Loopback-only preview · no telemetry · no result uploads · no application-code writes</footer>
</main><script src="/assets/app.js" defer></script></body></html>`;
}
