const $ = (id) => document.getElementById(id);
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const fmt = (v) => { try { return new Date(v).toLocaleString() } catch { return v } };
const WARN = ["EXPIRED", "REPLAY_BLOCKED", "ROLLBACK_BLOCKED"];
const GOOD = ["ACCEPTED", "CREATED", "ROTATED", "COMPLETED", "LOGIN_OK", "USER_CREATED", "USER_ENABLED", "PASSWORD_CHANGED", "PASSWORD_RESET"];
const tone = (s) => GOOD.includes(s) ? "" : [...WARN, "LOCKED", "USER_DISABLED"].includes(s) ? "warn" : "bad";
let me = null;
let toastTimer;
function toast(msg) { const el = $("toast"); el.textContent = msg; el.classList.add("show"); clearTimeout(toastTimer); toastTimer = setTimeout(() => el.classList.remove("show"), 2800) }
async function api(url, opts = {}) {
  const res = await fetch(url, opts);
  if (res.status === 401 && me) { me = null; showLogin("Your session has ended. Please sign in again.") }
  if (!res.ok) { let m = "Request failed"; try { m = (await res.json()).detail || m } catch {} throw new Error(m) }
  return res;
}
const getJSON = async (u, o) => (await api(u, o)).json();
function download(blob, name) { const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = name; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 1000) }

/* ---------- navigation ---------- */
const LABELS = { auto: "Auto demo", users: "Users", overview: "Overview", publisher: "Publisher", verify: "Verify an update", lab: "Attack lab", tools: "Keys & tools", audit: "Audit trail" };
function allowed(name) { const b = document.querySelector(`.nav-item[data-page="${name}"]`); return !b || !b.dataset.roles || b.dataset.roles.split(" ").includes(me?.role) }
function showPage(name) {
  if (!allowed(name)) { toast("Your role cannot open that page."); name = "overview" }
  document.querySelectorAll(".page").forEach(p => p.classList.remove("active"));
  $("page-" + name).classList.add("active");
  document.querySelectorAll(".nav-item").forEach(n => n.classList.toggle("active", n.dataset.page === name));
  $("crumb-current").textContent = LABELS[name];
  history.replaceState(null, "", "#" + name);
  ({ audit: loadAudit, tools: loadKeys, publisher: loadReleases, overview: loadOverview, users: loadUsers })[name]?.();
}
document.querySelectorAll(".nav-item").forEach(b => b.onclick = () => showPage(b.dataset.page));
document.querySelectorAll("[data-go]").forEach(b => b.onclick = () => showPage(b.dataset.go));


/* ---------- authentication ---------- */
function showLogin(msg = "") { resetWorkspace(); $("login-screen").classList.remove("hidden"); $("login-error").textContent = msg; $("login-pass").value = ""; $("login-user").focus() }
function applyUser(u) {
  resetWorkspace(); me = u; $("login-screen").classList.add("hidden");
  $("who-name").textContent = u.username; $("who-role").textContent = u.role; $("avatar").textContent = u.username.slice(0, 2).toUpperCase();
  document.querySelectorAll("[data-roles]").forEach(el => el.classList.toggle("hidden", !el.dataset.roles.split(" ").includes(u.role)));
  const want = location.hash.slice(1); showPage(LABELS[want] ? want : "overview");
}
$("login-form").addEventListener("submit", async e => {
  e.preventDefault(); const btn = $("login-btn"); btn.disabled = true; $("login-error").textContent = "";
  try { applyUser(await getJSON("/api/auth/login", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ username: $("login-user").value, password: $("login-pass").value }) })) }
  catch (err) { $("login-error").textContent = err.message; $("login-pass").value = "" } finally { btn.disabled = false }
});
$("logout-btn").onclick = async () => { await fetch("/api/auth/logout", { method: "POST" }); me = null; $("login-user").value = ""; showLogin() };
$("pw-btn").onclick = () => { $("pw-current").value = $("pw-new").value = ""; $("pw-dialog").showModal() };
$("pw-form").addEventListener("submit", async e => {
  if (e.submitter?.value !== "default") return;
  try { await getJSON("/api/auth/password", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ current: $("pw-current").value, new: $("pw-new").value }) }); toast("Password changed.") }
  catch (err) { e.preventDefault(); toast(err.message) }
});

/* ---------- users (admin) ---------- */
async function loadUsers() {
  try {
    const { items } = await getJSON("/api/users");
    $("user-body").innerHTML = items.map(u => `<tr><td><b>${esc(u.username)}</b></td><td><span class="role-badge">${esc(u.role)}</span></td><td><span class="status-pill ${u.active ? "" : "bad"}">${u.active ? "ACTIVE" : "DISABLED"}</span></td><td>${u.last_login ? esc(fmt(u.last_login)) : "never"}</td><td style="white-space:nowrap"><button class="small-action" data-reset="${u.id}">Reset password</button> ${u.username === me.username ? "" : `<button class="small-action" data-toggle="${u.id}">${u.active ? "Disable" : "Enable"}</button>`}</td></tr>`).join("");
    document.querySelectorAll("[data-toggle]").forEach(b => b.onclick = async () => { try { await getJSON(`/api/users/${b.dataset.toggle}/toggle`, { method: "POST" }); loadUsers() } catch (e) { toast(e.message) } });
    document.querySelectorAll("[data-reset]").forEach(b => b.onclick = async () => { const pw = prompt("New password for this user (min 8 characters):"); if (!pw) return; try { await getJSON(`/api/users/${b.dataset.reset}/password`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ password: pw }) }); toast("Password reset. The user was signed out.") } catch (e) { toast(e.message) } });
  } catch (e) { toast(e.message) }
}
$("nu-btn").onclick = async () => {
  try { await getJSON("/api/users", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ username: $("nu-name").value, password: $("nu-pass").value, role: $("nu-role").value }) }); $("nu-name").value = $("nu-pass").value = ""; toast("User created."); loadUsers() }
  catch (e) { toast(e.message) }
};

/* ---------- drag & drop on every dropzone ---------- */
document.querySelectorAll("[data-drop]").forEach(zone => {
  const input = zone.querySelector("input");
  ["dragenter", "dragover"].forEach(e => zone.addEventListener(e, ev => { ev.preventDefault(); zone.classList.add("drag") }));
  ["dragleave", "drop"].forEach(e => zone.addEventListener(e, ev => { ev.preventDefault(); zone.classList.remove("drag") }));
  zone.addEventListener("drop", ev => { if (ev.dataTransfer.files.length) { input.files = ev.dataTransfer.files; input.dispatchEvent(new Event("change")) } });
  input.addEventListener("change", () => { zone.classList.toggle("has", !!input.files[0]); const b = zone.querySelector("b"); if (input.files[0]) b.textContent = input.files[0].name });
});

/* ---------- overview ---------- */
function eventMarkup(i) {
  const t = tone(i.status);
  return `<div class="activity-item"><i class="activity-dot ${t}"></i><div class="activity-copy"><b>${esc(i.event.replace("_", " "))} · ${esc(i.app_name || "Platform")}</b><small>${esc(i.version || "")} ${i.created_at ? "· " + esc(fmt(i.created_at)) : ""}</small></div><span class="activity-status ${t}">${esc(i.status)}</span></div>`;
}
async function loadOverview() {
  try {
    const d = await getJSON("/api/overview"), s = d.stats;
    $("stat-total").textContent = s.total; $("stat-passed").textContent = s.passed; $("stat-blocked").textContent = s.blocked; $("stat-replay").textContent = s.replay + s.rollback;
    $("lg-pass").textContent = s.passed; $("lg-block").textContent = s.blocked; $("lg-pub").textContent = s.published;
    const pct = s.total ? Math.round(s.passed / s.total * 100) : null, dn = $("donut");
    dn.classList.toggle("empty", pct === null); dn.style.setProperty("--p", (pct ?? 0) + "%"); $("donut-pct").textContent = pct === null ? "–" : pct + "%";
    $("active-key").textContent = "key: " + d.keys;
  } catch (e) { toast(e.message) }
}
(function greet() {
  const now = new Date(), h = now.getHours();
  $("greeting").textContent = h < 12 ? "Good morning." : h < 18 ? "Good afternoon." : "Good evening.";
  $("today-label").textContent = now.toLocaleDateString(undefined, { weekday: "long", month: "long", day: "numeric" }).toUpperCase() + " · SECURITY SNAPSHOT";
})();

/* ---------- publisher ---------- */
let uploadMode = false;
function setMode(up) { uploadMode = up; $("mode-sample").classList.toggle("on", !up); $("mode-upload").classList.toggle("on", up); $("sample-box").classList.toggle("hidden", up); $("upload-box").classList.toggle("hidden", !up) }
$("mode-sample").onclick = () => setMode(false); $("mode-upload").onclick = () => setMode(true);
async function publish() {
  const btn = $("publish-button"); btn.disabled = true; btn.textContent = "Signing package…";
  try {
    const app = $("app-name").value.trim() || "Northstar Notes", ver = $("app-version").value.trim() || "1.0.0", exp = $("app-expiry").value;
    let data;
    if (uploadMode) {
      const f = $("publish-file").files[0]; if (!f) throw new Error("Choose a ZIP file first.");
      const fd = new FormData(); fd.append("package", f); fd.append("app_name", app); fd.append("version", ver); fd.append("expires_in_hours", exp);
      data = await getJSON("/api/publisher/upload", { method: "POST", body: fd });
    } else data = await getJSON(`/api/publisher/sample?app_name=${encodeURIComponent(app)}&version=${encodeURIComponent(ver)}&expires_in_hours=${exp}`, { method: "POST" });
    renderReceipt(data); toast("Update signed."); loadOverview(); loadReleases();
  } catch (e) { toast(e.message) } finally { btn.disabled = false; btn.innerHTML = "Generate signed update <span>→</span>" }
}
function renderReceipt(d) {
  $("publish-result").innerHTML = `<div class="receipt"><div class="receipt-top"><b>Release created</b><span class="success-tag">SIGNED</span></div>
  <div class="receipt-label">Application / version</div><div style="font-weight:600;margin:4px 0">${esc(d.app_name)} · ${esc(d.version)} · ${d.file_count} files</div>
  <div class="receipt-label">Update ID</div><div class="mono">${esc(d.update_id)}</div>
  <div class="receipt-label">Signing key · expiry</div><div class="mono">${esc(d.key_id)} · ${d.expires_at ? esc(fmt(d.expires_at)) : "never"}</div>
  <div class="receipt-label">Package SHA-256</div><div class="mono">${esc(d.package_sha256)}</div>
  <div class="receipt-label">HMAC-SHA256</div><div class="mono">${esc(d.hmac)}</div>
  <div class="receipt-actions"><a class="small-action" href="${d.package_url}">ZIP ↓</a><a class="small-action" href="/api/envelope/${d.update_id}">Envelope ↓</a><button class="small-action" id="verify-this">Verify this →</button></div></div>`;
  $("verify-this").onclick = () => loadRelease(d.update_id);
}
async function loadReleases() {
  try {
    const { items } = await getJSON("/api/releases");
    $("release-body").innerHTML = items.length ? items.map(r => `<tr><td>${esc(r.app_name)}</td><td>${esc(r.version)}</td><td class="mono" style="padding:4px 8px">${esc(r.key_id)}</td><td>${r.expires_at ? esc(fmt(r.expires_at)) : "—"}</td><td>${esc(fmt(r.created_at))}</td>
      <td style="white-space:nowrap"><a class="small-action" href="/api/download/${r.update_id}">ZIP</a> <a class="small-action" href="/api/envelope/${r.update_id}">JSON</a> <button class="small-action" data-verify="${r.update_id}">Verify</button></td></tr>`).join("") : '<tr><td colspan="6" class="empty-cell">No releases yet.</td></tr>';
    document.querySelectorAll("[data-verify]").forEach(b => b.onclick = () => loadRelease(b.dataset.verify));
  } catch (e) { toast(e.message) }
}
$("publish-button").onclick = publish; $("quick-publish").onclick = () => { showPage("publisher"); publish() };

/* ---------- verify ---------- */
function setFile(inputId, blob, name) { const dt = new DataTransfer(); dt.items.add(new File([blob], name)); const i = $(inputId); i.files = dt.files; i.dispatchEvent(new Event("change")) }
async function loadRelease(id) {
  try {
    setFile("package-file", await (await api("/api/download/" + id)).blob(), `update-${id}.zip`);
    setFile("envelope-file", await (await api("/api/envelope/" + id)).blob(), `update-${id}.json`);
    showPage("verify"); toast("Release loaded. Press “Run integrity verification”.");
  } catch (e) { toast(e.message) }
}
$("use-latest").onclick = async () => { try { const { items } = await getJSON("/api/releases"); items.length ? loadRelease(items[0].update_id) : toast("No releases yet. Publish one first.") } catch (e) { toast(e.message) } };
const CHECKS = { hmac: "HMAC authentication", key_trust: "Key trust", package_fingerprint: "Package fingerprint", file_manifest: "File manifest", freshness: "Freshness / expiry", replay_protection: "Replay protection", rollback_protection: "Version policy" };
const chipsFor = (c) => `<div class="chips">${Object.entries(c).map(([k, v]) => `<span class="chip ${v ? "ok" : "no"}">${v ? "✓" : "✕"} ${CHECKS[k]}</span>`).join("")}</div>`;
$("verify-form").addEventListener("submit", async e => {
  e.preventDefault(); const p = $("package-file").files[0], m = $("envelope-file").files[0]; if (!p || !m) return;
  const fd = new FormData(); fd.append("package", p); fd.append("envelope_file", m); fd.append("accept", $("accept-update").checked);
  const t = $("verify-result"); t.innerHTML = '<div class="empty-large"><b>Running security checks…</b></div>';
  try { renderVerification(await getJSON("/api/verify", { method: "POST", body: fd })); loadOverview() }
  catch (err) { t.innerHTML = `<div class="result-decision bad"><div class="decision-icon">✕</div><div><div class="decision-title">Could not verify package</div><div class="decision-sub">${esc(err.message)}</div></div></div>` }
});
function renderVerification(r) {
  const cls = r.valid ? "good" : (WARN.includes(r.status) ? "warn" : "bad");
  const title = r.valid ? (r.accepted ? "Update accepted" : "Integrity verified") : (cls === "warn" ? "Update blocked" : "Update rejected");
  const checks = Object.entries(r.checks).map(([k, v]) => `<div class="check-row"><span>${CHECKS[k]}</span><span class="${v ? "pass" : "fail"}">${v ? "PASS" : "FAILED"}</span></div>`).join("");
  const diff = [...r.changed_files.map(f => `<span class="tag c">~ ${esc(f)}</span>`), ...r.missing_files.map(f => `<span class="tag m">− ${esc(f)}</span>`), ...r.unexpected_files.map(f => `<span class="tag u">+ ${esc(f)}</span>`)].join("");
  $("verify-result").innerHTML = `<div class="result-decision ${cls}"><div class="decision-icon">${r.valid ? "✓" : cls === "warn" ? "!" : "✕"}</div><div><div class="decision-title">${title}</div><div class="decision-sub">${esc(r.app_name)} · v${esc(r.version)} · ${esc(r.status)}</div></div></div>
  <div class="check-list">${checks}</div>${diff ? `<div class="filediff">${diff}</div>` : ""}
  ${r.reasons.length ? `<ul class="reason-list">${r.reasons.map(x => `<li>${esc(x)}</li>`).join("")}</ul>` : ""}
  <div class="receipt-label" style="margin-top:14px">Update ID · key</div><div class="mono">${esc(r.update_id)} · ${esc(r.key_id)}</div>`;
}

/* ---------- attack lab ---------- */
const SCENARIOS = [
  ["tamper", "⌁", "var(--red)", "Package tampering", "A file inside the signed ZIP is modified after signing."],
  ["forged", "✎", "var(--violet)", "Forged metadata", "Envelope edited to say v9.9.9, but the attacker can’t recompute the HMAC."],
  ["replay", "↻", "var(--amber)", "Replay attack", "A previously accepted update is delivered a second time."],
  ["rollback", "⇣", "var(--cyan)", "Rollback / downgrade", "An older, validly signed release is pushed after a newer one."],
  ["expired", "⏱", "var(--amber)", "Expired release", "A valid signature used after its expiry time has passed."],
  ["unknown_key", "⚿", "var(--red)", "Unknown signing key", "Envelope claims a key id that isn’t in the trusted keyring."],
];
$("lab-grid").innerHTML = SCENARIOS.map((s, i) => `<article class="attack-card" style="--c:${s[2]}"><div class="attack-number">SCENARIO 0${i + 1}</div><div class="attack-icon">${s[1]}</div><h2>${s[3]}</h2><p>${s[4]}</p><button class="button button-outline full" data-run="${s[0]}">Simulate attack →</button></article>`).join("");
let labMode = "sample";
const setLab = (m) => { labMode = m; $("lab-sample").classList.toggle("on", m === "sample"); $("lab-upload").classList.toggle("on", m === "upload"); $("lab-drop").classList.toggle("hidden", m === "sample") };
$("lab-sample").onclick = () => setLab("sample"); $("lab-upload").onclick = () => setLab("upload");
document.querySelectorAll("[data-run]").forEach(b => b.onclick = () => {
  const f = $("lab-file").files[0];
  if (labMode === "upload" && !f) { toast("Choose your ZIP first."); return }
  runLab(b.dataset.run, labMode === "upload" ? f : null);
});
$("tamper-file").addEventListener("change", async e => {
  const f = e.target.files[0]; if (!f) return; const fd = new FormData(); fd.append("package", f);
  try { download(await (await api("/api/attack/tamper", { method: "POST", body: fd })).blob(), "tampered-update.zip"); toast("Tampered ZIP downloaded. Verify it with the original envelope.") } catch (err) { toast(err.message) }
});

/* ---------- keys & tools ---------- */
async function loadKeys() {
  try {
    const d = await getJSON("/api/keys");
    $("key-list").innerHTML = d.keys.map(k => `<div class="key-row ${k.active ? "on" : ""}"><span class="nav-icon">⚿</span><div><b>${esc(k.key_id)}</b><small>sha256:${esc(k.fingerprint)} · ${esc(fmt(k.created_at))}</small></div>${k.active ? '<span class="badge-active">ACTIVE</span>' : ""}</div>`).join("");
    $("active-key").textContent = "key: " + d.active;
  } catch (e) { toast(e.message) }
}
$("rotate-btn").onclick = async () => {
  if (!confirm("Create a new active signing key? Older keys remain trusted for verification.")) return;
  const btn = $("rotate-btn"); btn.disabled = true; btn.classList.add("rotating"); btn.textContent = "Rotating…";
  try {
    await new Promise(r => setTimeout(r, 1200));
    const d = await getJSON("/api/keys/rotate", { method: "POST" });
    await loadKeys();
    const row = document.querySelector("#key-list .key-row.on"); if (row) { row.classList.remove("fresh"); void row.offsetWidth; row.classList.add("fresh") }
    toast("New active key: " + d.active);
  } catch (e) { toast(e.message) }
  finally { btn.disabled = false; btn.classList.remove("rotating"); btn.textContent = "↻ Rotate key" }
};
$("hash-btn").onclick = async () => {
  const fd = new FormData(), f = $("hash-file").files[0];
  fd.append("text", $("hash-text").value); if (f) fd.append("file", f); fd.append("compare_tag", $("hash-compare").value);
  try {
    const r = await getJSON("/api/tools/hash", { method: "POST", body: fd });
    $("hash-out").innerHTML = `<div class="receipt-label" style="margin-top:16px">SHA-256 (${r.bytes} bytes)</div><div class="mono">${esc(r.sha256)}</div><div class="receipt-label">HMAC-SHA256 · ${esc(r.key_id)}</div><div class="mono">${esc(r.hmac)}</div>` +
      (r.match === undefined ? "" : `<div class="verdict" style="${r.match ? "" : "color:var(--red);background:rgba(248,113,113,.08);border-color:rgba(248,113,113,.3)"}">${r.match ? "✓ Tag matches (constant-time compare)" : "✕ Tag does not match"}</div>`);
  } catch (e) { toast(e.message) }
};

/* ---------- audit ---------- */
let auditItems = [];
async function loadAudit() {
  try { auditItems = (await getJSON("/api/audit")).items; const sel = $("audit-status"), cur = sel.value; sel.innerHTML = '<option value="">All statuses</option>' + [...new Set(auditItems.map(i => i.status))].map(s => `<option ${s === cur ? "selected" : ""}>${esc(s)}</option>`).join(""); renderAudit() } catch (e) { toast(e.message) }
}
function renderAudit() {
  const q = $("audit-search").value.toLowerCase(), st = $("audit-status").value;
  const rows = auditItems.filter(i => (!st || i.status === st) && [i.event, i.app_name, i.version, i.status].join(" ").toLowerCase().includes(q));
  $("audit-body").innerHTML = rows.length ? rows.map(i => `<tr class="click" data-row="${i.id}"><td>${esc(i.event)}</td><td>${esc(i.app_name || "—")}</td><td>${esc(i.version || "—")}</td><td><span class="status-pill ${tone(i.status)}">${esc(i.status)}</span></td><td>${esc(fmt(i.created_at))}</td></tr>
    <tr class="detail hidden" id="d-${i.id}"><td colspan="5"><pre>${esc(JSON.stringify(JSON.parse(i.detail || "{}"), null, 2))}\nentry_hash: ${esc(i.entry_hash || "(legacy row)")}</pre></td></tr>`).join("") : '<tr><td colspan="5" class="empty-cell">No matching events.</td></tr>';
  document.querySelectorAll("[data-row]").forEach(r => r.onclick = () => $("d-" + r.dataset.row).classList.toggle("hidden"));
}
$("audit-search").oninput = renderAudit; $("audit-status").onchange = renderAudit;
$("chain-btn").onclick = async () => {
  try { const r = await getJSON("/api/audit/chain"), el = $("chain-state"); el.className = "chain " + (r.valid ? "ok" : "bad");
    el.textContent = r.valid ? `✓ chain intact · ${r.checked} entries` : `✕ tampering detected at entry #${r.broken_at}` } catch (e) { toast(e.message) }
};

/* ---------- fresh workspace on sign in / sign out (server side history is kept) ---------- */
const DEFAULTS = { pub: $("publish-result").innerHTML, ver: $("verify-result").innerHTML, ids: {} };
document.querySelectorAll("[data-drop]").forEach(z => { const b = z.querySelector("b"); if (b) b.dataset.orig = b.textContent });
["app-name", "app-version", "app-expiry"].forEach(i => DEFAULTS.ids[i] = $(i).value);
function resetWorkspace() {
  document.querySelectorAll('input[type=file]').forEach(i => { i.value = "" });
  document.querySelectorAll("[data-drop]").forEach(z => { z.classList.remove("has", "drag"); const b = z.querySelector("b"); if (b && b.dataset.orig) b.textContent = b.dataset.orig });
  $("publish-result").className = "empty-large"; $("publish-result").innerHTML = DEFAULTS.pub;
  $("verify-result").className = "empty-large"; $("verify-result").innerHTML = DEFAULTS.ver;
  $("accept-update").checked = false; $("hash-text").value = ""; $("hash-compare").value = ""; $("hash-out").innerHTML = "";
  ["nu-name", "nu-pass", "pw-current", "pw-new"].forEach(i => { if ($(i)) $(i).value = "" });
  Object.entries(DEFAULTS.ids).forEach(([k, v]) => $(k).value = v);
  setMode(false); if (typeof setLab === "function") setLab("sample");
  if (typeof resetDemoUI === "function") resetDemoUI();
}
(async () => { try { applyUser(await getJSON("/api/me")) } catch { showLogin() } })();
