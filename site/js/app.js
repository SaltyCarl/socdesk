// app.js — boot order and wiring. Holds the DOM/module contract.
//
// LAYOUT CONTRACT (operational console, not editorial scroll):
//   * The topbar switches working surfaces in place — one view at a time.
//   * A lookup renders in the full-width verdict console (#console) directly
//     beneath the search, with NO scroll jump. Escape / Clear exits result
//     mode. The feed-detail rail (#rail) is a separate slot the verdict
//     never shares.
//   * `#q=<indicator>` in the hash makes any lookup shareable and restores it
//     on load.
import { loadAll, detectType, refang, esc, num, copyText } from "./data.js";
import { beginSession, pruneReviewed, clearAll, state } from "./state.js";
import { g, decode, sealStroke, EASE, DUR } from "./motion.js";
import { buildIndex, verdict, renderVerdict, splitIndicators, bulkRows,
         toCSV, toDefangedTxt, download } from "./verdict.js";
import { initBookmarklet } from "./bookmarklet.js";
import { setRelations, attachRelated } from "./related.js";
import { enrichInto, isEnrichable } from "./enrich-client.js";
import { renderChrome, initFeed, bindKeys, updateHandoff, renderItem,
         initVulns, renderBrief, renderHealth, renderRegistry,
         renderTrends, renderActors, initViews, showView } from "./views.js";
// toolbelt is imported dynamically below: a static import would take the whole
// module graph down if that file is missing or fails to parse.

const $ = s => document.querySelector(s);
const $$ = s => [...document.querySelectorAll(s)];

document.documentElement.classList.add("js");

(async function boot() {
  beginSession();

  // Masthead: full plate on the first visit only; a compact strip after —
  // the fold belongs to data. `lastVisit` is the previous session's marker,
  // so no extra storage key is needed.
  if (state.lastVisit) $("#masthead").classList.add("compact");

  // Wired before the data fetch on purpose: the install card needs only the
  // DOM, and an anchor whose href is still unset drags as nothing. Leaving it
  // until after `await loadAll()` left a real window where pulling the button
  // to the bookmarks bar produced a dead bookmark.
  initBookmarklet({
    link: $("#bmkLink"), hint: $("#bmkHint"), copy: $("#bmkCopy"), copyText,
  });

  const data = await loadAll();

  pruneReviewed(new Set((data.feed?.items ?? []).map(i => i.id)));
  const idx = buildIndex(data);
  setRelations(data.relations);

  initViews();
  renderChrome(data);
  renderBrief(data.brief);
  renderHealth(data.health);
  renderRegistry(data.sources);
  renderActors(data, name => runLookup(name, { reveal: true }));
  updateHandoff();

  // The Brief tab exists only when a brief has actually been published — an
  // empty state does not get prime navigation.
  if (data.brief) $("#navBrief").hidden = false;

  const rail = $("#rail");
  const consoleEl = $("#console");
  initFeed(data, item => renderItem(rail, item, ent => runLookup(ent, { reveal: true })));
  initVulns(data, cve => runLookup(cve, { reveal: true }));
  renderTrends(data.trends, cve => runLookup(cve, { reveal: true }));
  bindKeys();

  /* ---- verdict console ---- */
  const qEl = $("#q");

  function setHash(raw) {
    try { history.replaceState(null, "", "#q=" + encodeURIComponent(raw)); } catch {}
  }
  function clearConsole() {
    consoleEl.hidden = true;
    consoleEl.innerHTML = "";
    document.body.classList.remove("result");
    try { history.replaceState(null, "", location.pathname + location.search); } catch {}
  }
  // Clear control inside the console (delegated: content re-renders per lookup)
  consoleEl.addEventListener("click", e => {
    if (e.target.closest("[data-vc=clear]")) clearConsole();
  });
  document.addEventListener("keydown", e => {
    if (e.key === "Escape" && !consoleEl.hidden) clearConsole();
  });

  function openConsole(reveal) {
    consoleEl.hidden = false;
    document.body.classList.add("result");
    // Reveal is for lookups launched from deep inside a view (a CVE row, an
    // entity chip, the toolbelt) — pasting into the search never scrolls.
    if (reveal) consoleEl.scrollIntoView({ behavior: g ? "smooth" : "auto", block: "nearest" });
  }

  /**
   * One entry point for every lookup. `reveal` scrolls the console into view
   * for click-driven lookups only — paste + Enter never moves the page.
   */
  function runLookup(raw, { reveal = false } = {}) {
    const bulk = splitIndicators(raw);
    if (bulk.length > 1) return runBulk(bulk, { reveal });
    const v = verdict(raw, idx);
    if (!v) return;
    openConsole(reveal);
    setHash(refang(raw));
    if (v.kind === "profile") return renderProfile(v.row);
    renderVerdict(consoleEl, v, (el, vv) => {
      decode(el.querySelector("#vword"), vv.word, .7);
      const arc = el.querySelector(".arc");
      if (arc && g) requestAnimationFrame(() => requestAnimationFrame(() => {
        g.to(arc, { strokeDashoffset: arc.dataset.off, duration: DUR.draw, ease: EASE });
      }));
      else if (arc) arc.style.strokeDashoffset = arc.dataset.off;
      if (vv.tone === "red") sealStroke(el, "var(--mark)");
    });
    const t = detectType(refang(raw));
    if (t === "cve")
      attachRelated(consoleEl, [refang(raw).toUpperCase()], n => runLookup(n));
    // The core loop: for an indicator SOCDesk holds no corpus for, ask the live
    // /api/enrich fan-out and replace "NOT IN CORPUS" with the real multi-source
    // verdict + a ready-to-paste evidence card. Fire-and-forget: it renders its
    // own loading state and degrades to the static verdict on any failure, so it
    // must never block or throw into the lookup path.
    if (v.kind === "router" && isEnrichable(t))
      enrichInto(consoleEl, { type: t, indicator: v.q, verdict: v }).catch(() => {});
    drawHistory();
  }

  function runBulk(list, { reveal = false } = {}) {
    const rows = bulkRows(list, idx);
    openConsole(reveal);
    setHash(list.join(" "));
    consoleEl.innerHTML = `
      <div class="vc-head"><span class="caps tone-accent">Bulk lookup · ${num(rows.length)} indicators</span>
        <button class="act" data-vc="clear">Clear · Esc</button></div>
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
    consoleEl.querySelectorAll("[data-bulk]").forEach(b => b.onclick = () => ({
      csv: () => download(`socdesk-bulk-${stamp}.csv`, toCSV(rows), "text/csv"),
      json: () => download(`socdesk-bulk-${stamp}.json`, JSON.stringify(rows, null, 2), "application/json"),
      txt: () => download(`socdesk-bulk-${stamp}.txt`, toDefangedTxt(rows)),
    })[b.dataset.bulk]());
  }

  function renderProfile(p) {
    const base = p.kind === "actors" || p.kind === "actor" ? "groups" : "software";
    const url = `https://attack.mitre.org/${base}/${encodeURIComponent(p.attack_id)}/`;
    consoleEl.innerHTML = `
      <div class="vc-head"><span class="caps tone-accent">Profile · ${esc(p.attack_id)}
        · MITRE ATT&amp;CK</span>
        <button class="act" data-vc="clear">Clear · Esc</button></div>
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
    consoleEl.querySelectorAll("[data-sw]").forEach(b =>
      b.onclick = () => runLookup(b.dataset.sw));
    attachRelated(consoleEl, [p.name, ...(p.aliases ?? [])], n => runLookup(n));
    sealStroke(consoleEl, "var(--line-bright)");
  }

  /* ---- omnibox ---- */
  qEl.addEventListener("input", () => {
    const t = detectType(refang(qEl.value));
    const d = $("#detect");
    d.textContent = t.toUpperCase();
    d.style.display = t ? "block" : "none";
  });
  qEl.addEventListener("keydown", e => { if (e.key === "Enter") runLookup(qEl.value); });

  /* ---- hash deep-link: restore a shared lookup on load ----
     Arrivals here are lookup-first by intent — a shared link, or the
     bookmarklet firing from someone else's page — so the verdict has to be
     what they land on. Without `reveal` the console rendered correctly and
     then sat off-screen above whichever view and scroll position the last
     session left behind: a bookmarklet click landed on the toolbelt.

     Only genuine external navigation reaches this. Typing in the box calls
     setHash(), which uses replaceState and fires no hashchange, so a normal
     search still never moves the page. */
  function applyHash() {
    const m = location.hash.match(/^#q=(.+)$/);
    if (!m) return;
    let q = "";
    try { q = decodeURIComponent(m[1]); } catch { return; }
    qEl.value = q;
    qEl.dispatchEvent(new Event("input"));
    runLookup(q, { reveal: true });
  }
  applyHash();
  addEventListener("hashchange", applyHash);

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
  $("#handoffBtn").onclick = async () => {
    const b = $("#handoffBtn"), was = b.textContent;
    const items = Object.values(state.notable).sort((a, b) => a.ts.localeCompare(b.ts));
    const head = `# SOCDESK shift handoff — ${new Date().toISOString().slice(0, 16)}Z`;
    const text = !items.length
      ? `${head}\n\n_No items flagged notable this shift._`
      : [head, "", ...items.map(n =>
          `- **${n.title}** _(${n.source})_\n  ${n.url}\n  flagged ${n.ts.slice(0, 16)}Z`),
         "", `${items.length} item(s) flagged.`].join("\n");
    b.textContent = (await copyText(text)) ? "COPIED ✓" : "COPY BLOCKED";
    setTimeout(() => { b.textContent = was; updateHandoff(); }, 1200);
  };

  /* ---- clear analyst state (workstation hygiene) ---- */
  $("#clearState").onclick = e => {
    clearAll();
    e.target.textContent = "CLEARED ✓";
    setTimeout(() => {
      e.target.textContent = "Clear analyst state";
      // drop any #q= deep link BEFORE reloading — otherwise the restored
      // lookup immediately rewrites the history key we just wiped
      try { history.replaceState(null, "", location.pathname + location.search); } catch {}
      location.reload();
    }, 800);
  };

  /* ---- toolbelt (optional module) ---- */
  try {
    const { initToolbelt } = await import("./toolbelt/belt.js");
    initToolbelt({ onBulkLookup: list => runBulk(list, { reveal: true }) });
  } catch (err) {
    console.warn("toolbelt unavailable:", err.message);
  }

  /* ---- offline capability ---- */
  // Registered last, so a failure here can never block the app. Offline means
  // "the last pull, clearly labelled with its age" — never stale data dressed
  // as live; the masthead's elapsed counter keeps telling the truth either way.
  if ("serviceWorker" in navigator && location.protocol !== "file:") {
    navigator.serviceWorker.register("./sw.js").catch(() => {});
    addEventListener("offline", () => {
      $("#staleChips").insertAdjacentHTML("afterbegin",
        `<span class="stale-chip" id="offlineChip">OFFLINE · CACHED DATA</span>`);
    });
    addEventListener("online", () => $("#offlineChip")?.remove());
    if (!navigator.onLine) dispatchEvent(new Event("offline"));
  }

  /* ---- choreography ---- */
  decode($("#tagline"), "TRACK · VERIFY · VERDICT · PIVOT — REFRESHED EVERY 30 MINUTES");
})();
