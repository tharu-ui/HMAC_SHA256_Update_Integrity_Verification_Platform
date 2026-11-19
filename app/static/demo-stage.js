/* Animated auto demo: a visual stage, no explanatory paragraphs. Data still comes from the real engine. */
const IC = {
  file: '<path d="M6 3h8l4 4v14H6z"/><path d="M14 3v4h4"/>',
  box: '<path d="M3 8l9-5 9 5v8l-9 5-9-5z"/><path d="M3 8l9 5 9-5M12 13v8"/>',
  key: '<circle cx="8" cy="12" r="4"/><path d="M12 12h9M18 12v4M21 12v3"/>',
  shield: '<path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/><path d="M8.5 12l2.5 2.5 4.5-5"/>',
  check: '<path d="M5 12l5 5 9-10"/>',
  clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
  hood: '<path d="M12 3c-4 0-6 3-6 6v3l-2 6h16l-2-6V9c0-3-2-6-6-6z"/><circle cx="9.5" cy="11" r="1"/><circle cx="14.5" cy="11" r="1"/>',
  hash: '<path d="M9 4L7 20M17 4l-2 16M4 9h17M3 15h17"/>',
  env: '<rect x="3" y="6" width="18" height="13" rx="2"/><path d="M3 8l9 6 9-6"/>',
  user: '<circle cx="12" cy="8" r="4"/><path d="M4 21c0-4 4-6 8-6s8 2 8 6"/>',
  book: '<path d="M5 4h11a3 3 0 013 3v13H8a3 3 0 01-3-3z"/><path d="M5 17a3 3 0 013-3h11"/>',
  tag: '<path d="M4 4h8l8 8-8 8-8-8z"/><circle cx="8.5" cy="8.5" r="1.2"/>',
  lock: '<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V8a4 4 0 018 0v3"/>',
  unlock: '<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V8a4 4 0 017.5-2"/>',
  gear: '<circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3M4.9 4.9L7 7M17 17l2.1 2.1M4.9 19.1L7 17M17 7l2.1-2.1"/>'
};
const ic = (n, cls = "") => `<svg viewBox="0 0 24 24" class="${cls}">${IC[n]}</svg>`;
const mk = (t, c, h) => { const e = document.createElement(t); if (c) e.className = c; if (h != null) e.innerHTML = h; return e };
const node = (i, label, cls = "") => mk("div", "node " + cls, ic(i) + (label ? `<div class="nl">${esc(label)}</div>` : ""));
const D = (s, k) => s.details.filter(d => d.kind === k);

let demoRun = 0, demoPaused = false;
const speed = () => parseFloat($("demo-speed").value);
const sleep = (ms) => new Promise(res => {
  const id = demoRun; let t = 0;
  const tick = () => { if (id !== demoRun) return res(); if (demoPaused) return setTimeout(tick, 120); if (t >= ms * speed()) return res(); t += 40; setTimeout(tick, 40) };
  tick();
});
async function scramble(el, text, id) {
  if (speed() === 0) { el.textContent = text; return }
  const H = "0123456789abcdef", n = 12;
  for (let f = 1; f <= n; f++) {
    if (id !== demoRun) return;
    const keep = Math.floor(text.length * f / n); let s = text.slice(0, keep);
    for (let i = keep; i < text.length; i++) s += /[0-9a-f]/i.test(text[i]) ? H[Math.random() * 16 | 0] : text[i];
    el.textContent = s; await sleep(45);
  }
  el.textContent = text;
}
const stamp = (ok, text, sub) => mk("div", "stamp " + (ok ? "ok" : "bad"), esc(text) + (sub ? `<small>${esc(sub)}</small>` : ""));
const grid = (gap = 10) => { const g = mk("div"); g.style.cssText = `display:grid;gap:${gap}px`; return g };

async function compareViz(cv, d, id) {
  const box = mk("div", "cmpbox");
  const spans = [[d.a_label, d.a], [d.b_label, d.b]].map(([l, v]) => {
    const r = mk("div", "cmprow", `<small>${esc(l)}</small>`), sp = mk("span");
    sp.innerHTML = [...v].map(c => `<i>${esc(c)}</i>`).join(""); r.appendChild(sp); box.appendChild(r); return sp.children;
  });
  cv.appendChild(box); await sleep(450);
  const n = Math.max(d.a.length, d.b.length);
  for (let i = 0; i < n; i += 4) {
    if (id !== demoRun) return;
    for (let j = i; j < Math.min(i + 4, n); j++) spans.forEach(c => c[j]?.classList.add(d.a[j] === d.b[j] ? "m" : "x"));
    await sleep(55);
  }
  await sleep(250);
  return box;
}
async function fillScene(cv, rows, id, icon) {
  const box = mk("div", "fill");
  const list = rows.map(r => { const e = mk("div", "fill-row pend", `<span>${esc(r.label)}</span><b></b>`); box.appendChild(e); return [e, r] });
  cv.append(node(icon, ""), box); await sleep(400);
  for (const [e, r] of list) {
    if (id !== demoRun) return;
    e.classList.remove("pend"); const b = e.querySelector("b");
    if (r.kind === "mono") await scramble(b, r.value, id); else { b.textContent = r.value; await sleep(380) }
  }
}
const mutLabel = (s, t) => {
  if (s.mut) return s.mut;
  const x = s.title.toLowerCase();
  if (x.includes("tamper")) return "+ bytes in " + (t[0]?.value || "file");
  if (x.includes("forge")) return t[0]?.value || "forged";
  if (x.includes("replay")) return "REPLAY: same update ID";
  if (x.includes("roll")) return `v${t[1]?.value} < v${t[0]?.value}`;
  if (x.includes("expired")) return "EXPIRED";
  return t[0]?.value || "modified";
};

const SCENES = {
  async package(cv, s, id) {
    const items = D(s, "files")[0].items, row = mk("div", "row"), col = grid();
    const cards = items.map(f => { const c = mk("div", "fcard", ic("file") + esc(f.name) + `<span>${f.size} B</span>`); col.appendChild(c); return c });
    const box = mk("div", "node big", ic("box") + '<div class="badge">0</div><div class="nl">update.zip</div>');
    row.append(col, mk("div", "arrow"), box); cv.appendChild(row); await sleep(700);
    let n = 0;
    for (const c of cards) {
      if (id !== demoRun) return;
      c.classList.add("go"); await sleep(650); box.querySelector(".badge").textContent = ++n;
      box.classList.remove("bump"); void box.offsetWidth; box.classList.add("bump"); await sleep(220);
    }
    box.classList.add("ok");
  },
  async fingerprint(cv, s, id) {
    const t = D(s, "text")[0], m = D(s, "mono")[0], row = mk("div", "row"), mach = node("hash", "SHA256", "big spin");
    const hb = mk("div", "hashbox", `<small>${esc(t.value)}</small><span>…</span>`);
    row.append(node("box", "update.zip"), mk("div", "arrow"), mach); cv.append(row, hb); await sleep(600);
    await scramble(hb.querySelector("span"), m.value, id); mach.classList.remove("spin"); mach.classList.add("ok");
  },
  async envelope(cv, s, id) { await fillScene(cv, [...D(s, "text"), ...D(s, "mono")], id, "env") },
  async canon(cv, s, id) {
    const m = D(s, "mono"), t = D(s, "text")[0];
    const toks = m[0].value.replace(/…$/, "").split(/(?<=,)/).slice(0, 14), flow = mk("div", "chipflow");
    const els = toks.map(x => { const e = mk("span", "tok", esc(x)); e.style.transform = `translate(${(Math.random() - .5) * 170}px,${(Math.random() - .5) * 90}px) rotate(${(Math.random() - .5) * 40}deg)`; flow.appendChild(e); return e });
    cv.appendChild(flow); await sleep(900);
    for (const e of els) { e.style.transform = "none"; await sleep(110) }
    const hb = mk("div", "hashbox", `<small>${esc(t.value)} sorted, compact</small><span></span>`); cv.appendChild(hb);
    await scramble(hb.querySelector("span"), m[1].value, id);
  },
  async sign(cv, s, id) {
    const kid = D(s, "text")[0], tag = D(s, "mono")[1], row = mk("div", "row"), left = grid(40);
    left.append(node("env", "bytes"), node("key", kid.value));
    const forge = node("gear", "HMAC SHA256", "big spin"), seal = node("shield", "tag");
    row.append(left, mk("div", "arrow"), forge, mk("div", "arrow"), seal);
    const hb = mk("div", "hashbox", "<small>HMAC tag</small><span>…</span>"); cv.append(row, hb); await sleep(900);
    await scramble(hb.querySelector("span"), tag.value, id); forge.classList.remove("spin"); seal.classList.add("ok");
  },
  async inspect(cv, s, id) {
    const row = mk("div", "row"), z = mk("div", "scanbox"), list = mk("div", "ticks");
    z.appendChild(node("box", "", "big")); row.append(z, list); cv.appendChild(row);
    for (const it of D(s, "list")[0].items) { await sleep(600); list.appendChild(mk("div", "tickrow", ic("check") + esc(it.text))) }
    await sleep(400); z.classList.remove("scanbox"); z.firstChild.classList.add("ok");
  },
  async compare(cv, s, id) {
    const d = D(s, "compare")[0]; await compareViz(cv, d, id);
    const out = mk("div", "chips2"); out.appendChild(stamp(d.match, d.match ? "IDENTICAL" : "MISMATCH"));
    D(s, "text").forEach(t => out.appendChild(mk("div", "c2 ok", esc(t.value)))); cv.appendChild(out);
  },
  async keytrust(cv, s, id) {
    const [claim, inr] = D(s, "text"), ok = inr.value === "yes", row = mk("div", "row");
    const key = node("key", claim.value), lock = node("lock", "keyring", "big");
    key.style.transition = ".7s"; row.append(key, mk("div", "arrow"), lock); cv.appendChild(row); await sleep(1000);
    key.style.transform = "translateX(70px) scale(.85)"; await sleep(700);
    lock.querySelector("svg").innerHTML = IC[ok ? "unlock" : "lock"]; lock.classList.add(ok ? "ok" : "bad"); key.classList.add(ok ? "ok" : "bad");
    cv.appendChild(stamp(ok, ok ? "TRUSTED KEY" : "UNKNOWN KEY"));
  },
  async filesverify(cv, s, id) {
    const items = D(s, "files")[0].items, col = grid(), wrap = mk("div", "scanbox"); wrap.style.padding = "6px";
    const cards = items.map(f => { const c = mk("div", "fcard", ic("file") + esc(f.name) + `<span>${esc(f.sha)}</span>`); col.appendChild(c); return [c, f] });
    wrap.appendChild(col); cv.appendChild(wrap);
    for (const [c, f] of cards) {
      await sleep(750); const ok = f.state === "match";
      c.classList.add(ok ? "ok" : "no"); c.insertAdjacentHTML("beforeend", `<em>${ok ? "MATCH" : "CHANGED"}</em>`);
    }
    await sleep(300); wrap.classList.remove("scanbox");
  },
  async fresh(cv, s, id) {
    const t = D(s, "text"), row = mk("div", "row");
    const tiles = [["clock", "Expiry", t[0].value], ["book", "Replay ledger", "seen before: " + t[1].value], ["tag", "Version", `${t[2].value} → ${t[3].value}`]];
    const els = tiles.map(([i, l, v]) => { const w = mk("div", "tile"), n = node(i, l, "big spin"), tv = mk("div", "tv", esc(v)); tv.style.opacity = 0; w.append(n, tv); row.appendChild(w); return [n, tv] });
    cv.appendChild(row);
    for (const [n, tv] of els) { await sleep(800); n.classList.remove("spin"); n.classList.add("ok"); tv.style.transition = ".5s"; tv.style.opacity = 1 }
  },
  async decision(cv, s, id) {
    const shield = node("shield", "", "big"), chips = mk("div", "chips2"); cv.append(shield, chips);
    for (const [k, v] of Object.entries(D(s, "checks")[0].checks)) { await sleep(420); chips.appendChild(mk("div", "c2 " + (v ? "ok" : "no"), (v ? "✓ " : "✕ ") + esc(CHECKS[k] || k))) }
    await sleep(350); const ok = s.outcome === "ok"; shield.classList.add(ok ? "ok" : "bad"); cv.appendChild(stamp(ok, ok ? "ACCEPTED" : "REJECTED", s.status));
  },
  async attack(cv, s, id) {
    const t = D(s, "text"), cmp = D(s, "compare")[0], chk = D(s, "checks")[0], blocked = s.outcome === "ok";
    const lane = mk("div", "lane"), ver = node("shield", "verifier"), hood = mk("div", "hood", ic("hood")), pk = mk("div", "packet", ic("box") + ic("env"));
    lane.append(node("user", "publisher"), ver, hood, pk); cv.appendChild(lane);
    await sleep(500); pk.classList.add("mid"); await sleep(1200);
    hood.classList.add("show"); await sleep(450);
    pk.insertAdjacentHTML("beforeend", `<span class="mut">${esc(mutLabel(s, t))}</span>`); await sleep(900);
    hood.classList.remove("show"); pk.classList.add("hit"); await sleep(1100);
    pk.classList.add("dead"); ver.classList.add(blocked ? "ok" : "bad"); ver.classList.add("bump"); await sleep(800);
    lane.style.display = "none";
    if (cmp) await compareViz(cv, cmp, id);
    const chips = mk("div", "chips2"); cv.appendChild(chips);
    for (const [k, v] of Object.entries(chk.checks)) { await sleep(300); chips.appendChild(mk("div", "c2 " + (v ? "ok" : "no"), (v ? "✓ " : "✕ ") + esc(CHECKS[k] || k))) }
    await sleep(300); cv.appendChild(stamp(blocked, blocked ? "BLOCKED" : "NOT BLOCKED", s.status));
  },
  async audit(cv, s, id) {
    const [n, ci] = D(s, "text"), cnt = Math.min(+n.value || 5, 6), ch = mk("div", "cblocks"); cv.appendChild(ch);
    for (let i = 0; i < cnt; i++) { if (i) ch.appendChild(mk("div", "lnk")); ch.appendChild(mk("div", "blk", `<b>ENTRY</b>#${i + 1}`)); await sleep(380) }
    cv.appendChild(mk("div", "hashbox", `<small>entries checked</small>${esc(n.value)}`)); await sleep(400);
    cv.appendChild(stamp(ci.value === "yes", ci.value === "yes" ? "CHAIN INTACT" : "CHAIN BROKEN"));
  },
  async rotate(cv, s, id) {
    const [n, a] = D(s, "text"), cnt = Math.min(+n.value || 1, 5), row = mk("div", "row");
    for (let i = 0; i < cnt; i++) { const k = node("key", i ? "trusted" : a.value, i ? "" : "ok"); k.style.animationDelay = i * .15 + "s"; row.appendChild(k) }
    cv.appendChild(row); await sleep(1000);
    const nx = node("key", "next key"); nx.style.borderStyle = "dashed"; nx.style.opacity = .7; row.appendChild(nx);
    await sleep(600); cv.appendChild(mk("div", "c2 ok", "old keys keep verifying"));
  },
  async summary(cv, s, id) {
    const items = D(s, "list")[0].items, big = mk("div", "bigcount", `0<small> / ${items.length}</small>`), list = grid(7);
    cv.append(big, list); let c = 0;
    for (const it of items) {
      await sleep(480); const st = (it.text.match(/: ([A-Z_]+)$/) || [])[1] || "";
      list.appendChild(mk("div", "sumrow " + (it.ok ? "" : "no"), ic("shield") + esc(it.text.replace(/: [A-Z_]+$/, "")) + `<em>${it.ok ? "✓ " : "✕ "}${esc(st)}</em>`));
      if (it.ok) c++; big.innerHTML = `${c}<small> / ${items.length}</small>`;
    }
    await sleep(300); cv.appendChild(stamp(c === items.length, c === items.length ? "ALL ATTACKS BLOCKED" : "REVIEW RESULTS"));
  }
};
SCENES.labresult = async function (cv, s, id) {
  const blocked = s.blocked, shield = node("shield", "verifier", "big"), chips = mk("div", "chips2"); cv.append(shield, chips);
  for (const [k, v] of Object.entries(D(s, "checks")[0].checks)) { await sleep(420); chips.appendChild(mk("div", "c2 " + (v ? "ok" : "no"), (v ? "✓ " : "✕ ") + esc(CHECKS[k] || k))) }
  await sleep(350); const good = s.valid || blocked; shield.classList.add(good ? "ok" : "bad");
  cv.appendChild(stamp(good, s.valid ? "ACCEPTED" : blocked ? "BLOCKED" : "NOT BLOCKED", s.status));
};
const SCENE_BY_TITLE = [
  ["Build the update", "package"], ["Fingerprint", "fingerprint"], ["Assemble", "envelope"], ["Canonicalise", "canon"], ["Sign with", "sign"],
  ["Receive and inspect", "inspect"], ["Recompute", "compare"], ["signing key is trusted", "keytrust"], ["Compare the package", "compare"],
  ["every file", "filesverify"], ["freshness", "fresh"], ["Decision", "decision"], ["audit log", "audit"], ["rotation", "rotate"], ["Summary", "summary"]
];
const pickScene = (s) => s.title.startsWith("Attack") ? "attack" : (SCENE_BY_TITLE.find(([k]) => s.title.includes(k)) || [])[1];
const ACTORS = { "1": ["user", "Publisher"], "2": ["shield", "Verifier"], "3": ["hood", "Attacker"], "4": ["book", "Audit"] };
function setPills(phases, active, done) { $("phase-pills").innerHTML = phases.map((p, i) => `<span class="pill ${i < done ? "done" : i === active ? "on" : ""}">${esc(p)}</span>`).join("") }

async function runDemo() {
  const id = ++demoRun; demoPaused = false;
  const btn = $("demo-start"), pause = $("demo-pause"), stage = $("stage"), cv = $("canvas");
  stage.classList.remove("paused"); stage.classList.toggle("instant", speed() === 0);
  btn.disabled = true; btn.textContent = "Running…"; $("demo-bar").style.width = "0"; $("demo-count").textContent = "Preparing…";
  cv.innerHTML = '<div class="idle"><div class="idle-shield"></div><b>Starting the engine</b></div>';
  let trace;
  try { trace = await getJSON("/api/demo/run", { method: "POST" }) } catch (e) { toast(e.message); btn.disabled = false; btn.textContent = "▶ Start automated demo"; return }
  pause.classList.remove("hidden"); pause.textContent = "❚❚ Pause";
  const phases = [...new Set(trace.steps.map(s => s.phase))], total = trace.steps.length;
  $("dots").innerHTML = trace.steps.map(() => "<i></i>").join(""); const dots = $("dots").children;
  for (const s of trace.steps) {
    if (id !== demoRun) return;
    const pi = phases.indexOf(s.phase), [ai, al] = ACTORS[s.phase[0]] || ["gear", ""], atk = s.phase[0] === "3";
    setPills(phases, pi, pi); $("demo-count").textContent = `Step ${s.n} of ${total}`; $("demo-note").textContent = s.phase.replace(/^\d · /, "");
    $("demo-bar").style.width = ((s.n - 1) / total * 100) + "%";
    for (let i = 0; i < dots.length; i++) dots[i].className = i < s.n - 1 ? "done" : i === s.n - 1 ? "on" : "";
    const ac = $("actor"); ac.className = "actor on" + (atk ? " atk" : ""); ac.innerHTML = `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.8">${IC[ai]}</svg>${al}`;
    $("cap-num").textContent = String(s.n).padStart(2, "0"); $("cap-title").textContent = s.title; $("cap-phase").textContent = s.phase.replace(/^\d · /, "");
    cv.innerHTML = ""; $("stage").scrollIntoView({ behavior: speed() === 0 ? "auto" : "smooth", block: "nearest" });
    try { await (SCENES[pickScene(s)] || (async (c, st, i) => fillScene(c, [...D(st, "text"), ...D(st, "mono")], i, "gear")))(cv, s, id) } catch (e) { console.error(e) }
    if (id !== demoRun) return;
    if (s.outcome === "bad") dots[s.n - 1].className = "bad";
    await sleep(1100);
  }
  if (id !== demoRun) return;
  for (const d of dots) if (d.className !== "bad") d.className = "done";
  setPills(phases, -1, phases.length); $("demo-bar").style.width = "100%"; $("demo-count").textContent = "Complete";
  $("demo-note").textContent = `${trace.blocked} of ${trace.attacks} attacks blocked.`;
  btn.disabled = false; btn.textContent = "↻ Run again"; pause.classList.add("hidden"); loadOverview(); toast("Automated demo complete.");
}
$("demo-start").onclick = runDemo;
$("demo-pause").onclick = () => { demoPaused = !demoPaused; $("stage").classList.toggle("paused", demoPaused); $("demo-pause").textContent = demoPaused ? "▶ Resume" : "❚❚ Pause" };

/* ---------- attack lab: dedicated simulation window ---------- */
const LAB_MUT = { tamper: "+ bytes injected", forged: "version → 9.9.9", replay: "REPLAY: same update ID", rollback: "older version", expired: "EXPIRED", unknown_key: "attacker-key-01" };
let simData = null;
async function playSim(r) {
  const id = ++demoRun; demoPaused = false;
  const cv = $("sim-canvas"), dots = $("sim-dots"), st = $("sim-stage");
  st.classList.toggle("instant", speed() === 0); $("sim-foot").innerHTML = ""; $("sim-replay").disabled = true;
  dots.innerHTML = r.steps.map(() => "<i></i>").join("");
  for (let i = 0; i < r.steps.length; i++) {
    if (id !== demoRun) return;
    const x = r.steps[i], last = i === r.steps.length - 1;
    const s = { valid: x.valid, blocked: !x.valid, status: x.status, details: [{ kind: "checks", checks: x.checks }] };
    [...dots.children].forEach((d, k) => d.className = k < i ? "done" : k === i ? "on" : "");
    const ac = $("sim-actor"); ac.className = "actor on";
    ac.innerHTML = `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.8">${IC.shield}</svg>Verifier`;
    $("sim-num").textContent = String(i + 1).padStart(2, "0"); $("sim-cap").textContent = x.label; $("sim-phase").textContent = x.note;
    cv.innerHTML = "";
    try { await SCENES.labresult(cv, s, id) } catch (e) { console.error(e) }
    if (id !== demoRun) return;
    await sleep(last ? 300 : 1000);
  }
  [...dots.children].forEach(d => d.className = "done");
  $("sim-foot").innerHTML = `<div class="verdict ${r.blocked ? "" : "no"}">${r.blocked ? "Attack blocked by the verification engine." : "Attack was NOT blocked."}</div>` +
    r.steps.map((x, i) => `<div class="sim-step"><b>${i + 1}. ${esc(x.label)}</b><span class="status-pill ${tone(x.status)}">${esc(x.status)}</span></div>${x.reasons.length ? `<ul class="reason-list">${x.reasons.map(q => `<li>${esc(q)}</li>`).join("")}</ul>` : ""}`).join("");
  $("sim-replay").disabled = false; loadOverview();
}
async function runLab(scenario, file) {
  const dlg = $("sim-dialog"); demoRun++;
  const meta = (SCENARIOS.find(s => s[0] === scenario) || [])[3] || "Attack";
  $("sim-title").textContent = meta; $("sim-eyebrow").textContent = "SIMULATION · " + (file ? file.name.toUpperCase() : "SAMPLE BUNDLE");
  $("sim-canvas").innerHTML = '<div class="idle"><div class="idle-shield"></div><b>Running on the real engine</b></div>';
  $("sim-foot").innerHTML = ""; $("sim-dots").innerHTML = ""; $("sim-cap").textContent = "Preparing"; $("sim-num").textContent = "00"; $("sim-phase").textContent = ""; $("sim-actor").className = "actor";
  $("sim-replay").disabled = true; if (!dlg.open) dlg.showModal();
  try {
    const fd = new FormData(); if (file) fd.append("package", file);
    simData = await getJSON("/api/lab/run/" + scenario, { method: "POST", body: fd });
    await playSim(simData);
  } catch (e) { toast(e.message); $("sim-canvas").innerHTML = `<div class="idle"><b>${esc(e.message)}</b></div>`; $("sim-replay").disabled = true }
}
$("sim-replay").onclick = () => simData && playSim(simData);
$("sim-close").onclick = () => { demoRun++; $("sim-dialog").close() };
$("sim-dialog").addEventListener("cancel", () => demoRun++);

function resetDemoUI() {
  demoRun++; demoPaused = false; $("stage").classList.remove("paused");
  $("canvas").innerHTML = '<div class="idle"><div class="idle-shield"></div><b>Press start to play the walkthrough</b></div>';
  $("dots").innerHTML = ""; $("actor").className = "actor"; $("cap-num").textContent = "00"; $("cap-title").textContent = "Ready"; $("cap-phase").textContent = "";
  $("demo-bar").style.width = "0"; $("demo-count").textContent = "Ready"; $("demo-note").textContent = "Computed live by the real engine"; $("phase-pills").innerHTML = "";
  $("demo-start").disabled = false; $("demo-start").textContent = "▶ Start automated demo"; $("demo-pause").classList.add("hidden");
  simData = null; if ($("sim-dialog").open) $("sim-dialog").close();
}
