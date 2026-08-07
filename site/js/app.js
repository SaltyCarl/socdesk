// app.js — boot order and wiring. Holds the DOM/module contract.
import { loadAll, detectType, refang, esc, num } from "./data.js";
import { beginSession, pruneReviewed, clearAll, state } from "./state.js";
import { g, decode, onEnter, sealStroke, sectionTimeline, EASE, DUR } from "./motion.js";
import { buildIndex, verdict, renderVerdict, splitIndicators, bulkRows,
         toCSV, toDefangedTxt, download } from "./verdict.js";
import { renderChrome, initFeed, bindKeys, updateHandoff, renderItem,
         initVulns, renderBrief, renderHealth, renderRegistry } from "./views.js";
// toolbelt is imported dynamically below: a static import would take the whole
// module graph down if that file is missing or fails to parse.

const $ = s => document.querySelector(s);
const $$ = s => [...document.querySelectorAll(s)];

document.documentElement.classList.add("js");

(async function boot() {
  beginSession();
  const data = await loadAll();

  if (!data.feed) {
    $("#feedRows").innerHTML =
      `<div class="row"><span class="tag tone-muted">offline</span>
       <div><div class="t">No collected data available</div>
       <div class="s">The pipeline has not published yet, or the data files
       could not be loaded. Everything else on this page still works.</div></div>
       <div class="right"></div></div>`;
  }

  pruneReviewed(new Set((data.feed?.items ?? []).map(i => i.id)));
  const idx = buildIndex(data);

  renderChrome(data);
  renderBrief(data.brief);
  renderHealth(data.health);
  renderRegistry(data.sources);
  updateHandoff();

  const rail = $("#rail");
  initFeed(data, item => renderItem(rail, item, ent => runLookup(ent)));
  initVulns(data, cve => runLookup(cve));
  bindKeys();

  /* ---- omnibox ---- */
  const qEl = $("#q");
  qEl.addEventListener("input", () => {
    const t = detectType(refang(qEl.value));
    const d = $("#detect");
    d.textContent = t.toUpperCase();
    d.style.display = t ? "block" : "none";
  });
  qEl.addEventListener("keydown", e => { if (e.key === "Enter") runLookup(qEl.value); });

  function runLookup(raw) {
    const bulk = splitIndicators(raw);
    if (bulk.length > 1) return runBulk(bulk);
    const v = verdict(raw, idx);
    if (!v) return;
    if (v.kind === "profile") return renderProfile(v.row);
    renderVerdict(rail, v, (el, vv) => {
      decode(el.querySelector("#vword"), vv.word, .7);
      const arc = el.querySelector(".arc");
      if (arc && g) requestAnimationFrame(() => requestAnimationFrame(() => {
        g.to(arc, { strokeDashoffset: arc.dataset.off, duration: DUR.draw, ease: EASE });
      }));
      else if (arc) arc.style.strokeDashoffset = arc.dataset.off;
      if (vv.tone === "red") sealStroke(el, "var(--mark)");
    });
    drawHistory();
    $("#operations").scrollIntoView({ behavior: g ? "smooth" : "auto" });
  }

  function runBulk(list) {
    const rows = bulkRows(list, idx);
    rail.innerHTML = `
      <div class="rail-h"><span class="caps tone-accent">Bulk lookup</span>
        <span class="caps sev-unknown">${num(rows.length)} indicators</span></div>
      <div class="ev"><div class="l">Results</div>
        ${rows.map(r => `<div class="ev-row">
          <span class="k tone-${esc(r.tone)}">${esc(r.q)}</span>
          <span class="d">${esc(r.type)} · ${esc(r.word)}</span></div>`).join("")}</div>
      <div class="pivots">
        <button class="pivot" data-bulk="csv">CSV ↓</button>
        <button class="pivot" data-bulk="json">JSON ↓</button>
        <button class="pivot" data-bulk="txt">Defanged TXT ↓</button>
      </div>`;
    const stamp = new Date().toISOString().slice(0, 10);
    rail.querySelectorAll("[data-bulk]").forEach(b => b.onclick = () => ({
      csv: () => download(`vigil-bulk-${stamp}.csv`, toCSV(rows), "text/csv"),
      json: () => download(`vigil-bulk-${stamp}.json`, JSON.stringify(rows, null, 2), "application/json"),
      txt: () => download(`vigil-bulk-${stamp}.txt`, toDefangedTxt(rows)),
    })[b.dataset.bulk]());
    $("#operations").scrollIntoView({ behavior: g ? "smooth" : "auto" });
  }

  function renderProfile(p) {
    const base = p.kind === "actors" ? "groups" : "software";
    const url = `https://attack.mitre.org/${base}/${encodeURIComponent(p.attack_id)}/`;
    rail.innerHTML = `
      <div class="rail-h"><span class="caps tone-accent">Profile · ${esc(p.attack_id)}</span>
        <span class="caps sev-unknown">MITRE ATT&amp;CK</span></div>
      <div class="rail-body">
        <div class="rail-title">${esc(p.name)}</div>
        ${p.aliases?.length ? `<div class="mono sev-unknown">${esc(p.aliases.join(" · "))}</div>` : ""}
        <p class="rail-text">${esc((p.description || "").slice(0, 600))}</p>
        ${p.techniques?.length ? `<div class="vtags">${p.techniques.slice(0, 12).map(t =>
          `<span class="vtag tone-muted">${esc(t)}</span>`).join("")}</div>` : ""}
      </div>
      ${p.software?.length ? `<div class="ev"><div class="l">Associated software</div>
        <div class="pivots">${p.software.slice(0, 10).map(s =>
          `<button class="pivot" data-sw="${esc(s)}">${esc(s)}</button>`).join("")}</div></div>` : ""}
      <div class="pivots">
        <a class="pivot" href="${url}" target="_blank" rel="noopener noreferrer">ATT&amp;CK ↗</a>
      </div>`;
    rail.querySelectorAll("[data-sw]").forEach(b => b.onclick = () => runLookup(b.dataset.sw));
    sealStroke(rail, "var(--line-bright)");
  }

  /* ---- try chips from real data ---- */
  const topKev = (data.cves?.cves ?? []).filter(c => c.kev)
    .sort((a, b) => (b.epss ?? 0) - (a.epss ?? 0))[0];
  const samples = [topKev?.cve, "185.220.101.42", "volt typhoon"].filter(Boolean);
  $("#exRow").insertAdjacentHTML("beforeend", samples.map(s =>
    `<button class="ex-chip" data-q="${esc(s)}">${esc(s)}</button>`).join(""));
  $$(".ex-chip").forEach(c => c.onclick = () => {
    qEl.value = c.dataset.q;
    qEl.dispatchEvent(new Event("input"));
    runLookup(c.dataset.q);
  });

  /* ---- lookup history ---- */
  function drawHistory() {
    const row = $("#histRow");
    if (!state.history.length) { row.innerHTML = ""; return; }
    row.innerHTML = `<span class="ex-label">Recent</span>` + state.history.map(h =>
      `<button data-h="${esc(h.q)}">${esc(h.q)} <span class="vd tone-${
        h.verdict?.includes("EXPLOITED") ? "red" : "muted"}">${esc(h.verdict)}</span></button>`
    ).join("");
    row.querySelectorAll("[data-h]").forEach(b => b.onclick = () => runLookup(b.dataset.h));
  }
  drawHistory();

  /* ---- handoff digest ---- */
  $("#handoffBtn").onclick = () => {
    const items = Object.values(state.notable).sort((a, b) => a.ts.localeCompare(b.ts));
    const head = `# VIGIL shift handoff — ${new Date().toISOString().slice(0, 16)}Z`;
    const text = !items.length
      ? `${head}\n\n_No items flagged notable this shift._`
      : [head, "", ...items.map(n =>
          `- **${n.title}** _(${n.source})_\n  ${n.url}\n  flagged ${n.ts.slice(0, 16)}Z`),
         "", `${items.length} item(s) flagged.`].join("\n");
    navigator.clipboard?.writeText(text);
    const b = $("#handoffBtn"), was = b.textContent;
    b.textContent = "COPIED ✓";
    setTimeout(() => { b.textContent = was; updateHandoff(); }, 1200);
  };

  /* ---- clear analyst state (workstation hygiene) ---- */
  $("#clearState").onclick = e => {
    clearAll();
    e.target.textContent = "CLEARED ✓";
    setTimeout(() => { e.target.textContent = "Clear analyst state"; location.reload(); }, 800);
  };

  /* ---- toolbelt (optional module) ---- */
  try {
    const { initToolbelt } = await import("./toolbelt/belt.js");
    initToolbelt({ onBulkLookup: list => runBulk(list) });
  } catch (err) {
    console.warn("toolbelt unavailable:", err.message);
  }

  /* ---- choreography ---- */
  decode($("#tagline"), "TRACK · VERIFY · VERDICT · PIVOT — REFRESHED EVERY 30 MINUTES");
  $$("section").forEach(sec => sectionTimeline(sec));
  if (!g) $$(".reveal").forEach(el => el.classList.add("in"));
  else {
    // threshold MUST be 0: a percentage threshold can never be satisfied by an
    // element taller than the viewport (the feed is hundreds of rows), which
    // would leave it permanently invisible.
    const io = new IntersectionObserver(es => es.forEach(e => {
      if (e.isIntersecting) { e.target.classList.add("in"); io.unobserve(e.target); }
    }), { threshold: 0, rootMargin: "0px 0px -6% 0px" });
    $$(".reveal").forEach(el => io.observe(el));
    // Safety net: nothing may stay hidden because motion failed to fire.
    setTimeout(() => $$(".reveal:not(.in)").forEach(el => {
      const r = el.getBoundingClientRect();
      if (r.top < innerHeight) el.classList.add("in");
    }), 1200);
  }
})();
