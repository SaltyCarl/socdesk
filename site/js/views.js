// views.js — chrome, feed, rail detail, vulnerability triage, brief, health,
// registry. Every data-derived string goes through esc(); every href through
// safeUrl(). No inline styles or handlers (strict CSP, no unsafe-inline).
import { esc, safeUrl, rel, day, num, elapsed, nextPull, staleness,
         copyToButton } from "./data.js";
import { state, toggleReviewed, toggleNotable, notableCount, watchHit,
         addWatch, removeWatch } from "./state.js";
import { countUp, onEnter, reflow, trackPointer, tick, startTicker } from "./motion.js";

const $ = s => document.querySelector(s);
const $$ = s => [...document.querySelectorAll(s)];

/* ---------------- chrome ---------------- */
export function renderChrome(data) {
  const feed = data.feed, health = data.health;
  const total = (feed?.items?.length ?? 0) + (data.cves?.cves?.length ?? 0)
    + (data.actors?.profiles?.length ?? 0) + (data.malware?.profiles?.length ?? 0);

  const gen = feed?.generated_at;
  const d = gen ? new Date(gen) : null;
  $("#mastEdition").textContent = d
    ? `${gen.slice(0, 10)} · ${d.toLocaleDateString("en-US", { weekday: "short" }).toUpperCase()}`
    : "—";
  countUp($("#mastCount"), total);
  tick($("#mastRefreshed"), () => elapsed(gen));
  tick($("#mastNext"), () => nextPull());

  const ok = health?.sources?.filter(s => s.ok).length ?? 0;
  const all = health?.sources?.length ?? 0;
  $("#liveCount").textContent = `${ok}/${all} collectors online`;

  $("#staleChips").innerHTML = staleness(data)
    .map(l => `<span class="stale-chip">${esc(l)}</span>`).join("");

  // ticker from real data
  const kev = (data.cves?.cves ?? []).filter(c => c.kev)
    .sort((a, b) => (b.epss ?? 0) - (a.epss ?? 0)).slice(0, 2);
  const items = feed?.items ?? [];
  const pick = cat => items.filter(i => i.category === cat).slice(0, 2);
  const ticks = [
    ...kev.map(c => ["NEW KEV", `${c.cve} · ${(c.products?.[0] || c.vendors?.[0] || "").slice(0, 40)}`, "tone-red"]),
    ...pick("ransomware").map(i => ["RANSOMWARE", i.title.slice(0, 70), "tone-orange"]),
    ...pick("vulnerability").map(i => ["VULNERABILITY", i.title.slice(0, 70), "tone-gold"]),
    ...pick("apt").map(i => ["APT", i.title.slice(0, 70), "tone-accent"]),
  ].filter(t => t[1]);
  const html = ticks.map(t =>
    `<span class="tick-item"><b class="${esc(t[2])}">${esc(t[0])}</b> · ${esc(t[1])}</span>`).join("");
  $("#tickTrack").innerHTML = html + html;     // duplicated for the -50% loop
  startTicker($("#tickTrack"));

  // stat band counts
  $$("#band button").forEach(b => {
    const cat = b.dataset.cat;
    const n = cat === "all" ? items.length : items.filter(i => i.category === cat).length;
    onEnter(b, () => countUp(b.querySelector("b"), n));
  });
}

/* ---------------- feed ---------------- */
let feedState = { items: [], filter: "all", q: "", sel: 0, cursor: 0,
                  onSelect: null, loaded: true };

/**
 * Degraded state for a feed payload that did not load. It lives HERE, in the
 * only function that owns #feedRows: written anywhere else it is silently
 * overwritten by the first render() and the page goes blank instead of
 * explaining itself.
 */
const OFFLINE_ROW =
  `<div class="row"><span class="tag tone-muted">offline</span>
   <div><div class="t">No collected data available</div>
   <div class="s">The pipeline has not published yet, or the data files
   could not be loaded. Everything else on this page still works.</div></div>
   <div class="right"></div></div>`;

export function initFeed(data, onSelect) {
  feedState.items = data.feed?.items ?? [];
  feedState.loaded = !!data.feed;
  feedState.onSelect = onSelect;

  const cats = ["all", ...new Set(feedState.items.map(i => i.category))];
  $("#filters").innerHTML = cats.map(c => {
    const n = c === "all" ? feedState.items.length
      : feedState.items.filter(i => i.category === c).length;
    return `<button class="fchip${c === "all" ? " on" : ""}" data-f="${esc(c)}">${esc(c)}<b>${num(n)}</b></button>`;
  }).join("");
  $$("#filters .fchip").forEach(b => b.onclick = () => setFilter(b.dataset.f));
  $$("#band button").forEach(b => b.onclick = () => setFilter(b.dataset.cat));

  let t;
  $("#q2").addEventListener("input", e => {
    clearTimeout(t);
    t = setTimeout(() => { feedState.q = e.target.value.toLowerCase(); render(); }, 150);
  });

  $("#exportBtn").onclick = () => {
    const blob = new Blob([JSON.stringify(visible(), null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `socdesk-feed-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
  };

  trackPointer($("#feedRows"), ".row");
  $("#feedRows").addEventListener("click", e => {
    const row = e.target.closest(".row");
    if (!row) return;
    if (e.target.closest("[data-act=review]")) {
      e.stopPropagation();
      toggleReviewed(row.dataset.id);
      row.classList.toggle("reviewed");
      return;
    }
    select([...$$("#feedRows .row")].indexOf(row));
  });

  render();
}

function setFilter(f) {
  feedState.filter = f;
  feedState.sel = 0; feedState.cursor = 0;
  $$("#filters .fchip").forEach(x => x.classList.toggle("on", x.dataset.f === f));
  $$("#band button").forEach(x => x.classList.toggle("on", x.dataset.cat === f));
  reflow(render);
}

function visible() {
  return feedState.items.filter(i =>
    (feedState.filter === "all" || i.category === feedState.filter) &&
    (!feedState.q ||
      (i.title + " " + i.summary + " " + Object.values(i.entities || {}).flat().join(" "))
        .toLowerCase().includes(feedState.q)));
}

function render() {
  if (!feedState.loaded) {
    $("#feedRows").innerHTML = OFFLINE_ROW;
    $("#fhCount").textContent = "Unavailable";
    $("#fhCat").textContent = feedState.filter;
    $("#resChip").textContent = "0 results";
    return;
  }
  const items = visible();
  const boundaryAt = state.lastVisit
    ? items.findIndex(i => i.published_at <= state.lastVisit) : -1;

  $("#feedRows").innerHTML = items.map((i, n) => {
    const hit = watchHit([...(i.entities?.vendors ?? []), i.title]);
    const boundary = n === boundaryAt && n > 0
      ? `<div class="new-boundary">${num(n)} new since last visit</div>` : "";
    return boundary + `
      <div class="row${n === feedState.sel ? " sel" : ""}${state.reviewed[i.id] ? " reviewed" : ""}"
           data-id="${esc(i.id)}" data-i="${n}">
        <span class="tag cat-${esc(i.category)}">${esc(i.category)}</span>
        <div><div class="src">${esc(i.source)}</div>
          <div class="t">${esc(i.title)}</div>
          <div class="s">${esc(i.summary)}</div></div>
        <div class="right">
          <span class="tm">${esc(rel(i.published_at))}</span>
          ${hit ? `<span class="wl">${esc(hit)}</span>` : ""}
          <button class="rv" data-act="review" title="Mark reviewed">✓</button>
        </div>
      </div>`;
  }).join("");

  $("#fhCount").textContent = `Showing ${num(items.length)} of ${num(feedState.items.length)}`;
  $("#fhCat").textContent = feedState.filter;
  $("#resChip").textContent = `${num(items.length)} results`;
  const cur = items[Math.min(feedState.sel, items.length - 1)];
  if (cur) feedState.onSelect?.(cur);
}

function select(n) {
  const items = visible();
  if (!items.length) return;
  feedState.sel = feedState.cursor = Math.max(0, Math.min(n, items.length - 1));
  $$("#feedRows .row").forEach((r, i) => r.classList.toggle("sel", i === feedState.sel));
  feedState.onSelect?.(items[feedState.sel]);
}

/** j/k/r/n/Enter keyboard triage. */
export function bindKeys() {
  document.addEventListener("keydown", e => {
    const typing = ["INPUT", "TEXTAREA"].includes(document.activeElement?.tagName);
    if (e.key === "/" && !typing) { e.preventDefault(); $("#q")?.focus(); return; }
    if (typing) return;
    const items = visible();
    if (e.key === "j") { e.preventDefault(); select(feedState.sel + 1); scrollSel(); }
    if (e.key === "k") { e.preventDefault(); select(feedState.sel - 1); scrollSel(); }
    if (e.key === "r") {
      const i = items[feedState.sel]; if (!i) return;
      toggleReviewed(i.id);
      $$("#feedRows .row")[feedState.sel]?.classList.toggle("reviewed");
    }
    if (e.key === "n") {
      const i = items[feedState.sel]; if (!i) return;
      toggleNotable(i); updateHandoff();
    }
  });
}
const scrollSel = () =>
  $$("#feedRows .row")[feedState.sel]?.scrollIntoView({ block: "nearest" });

export function updateHandoff() {
  const n = notableCount();
  const btn = $("#handoffBtn");
  if (btn) btn.textContent = n ? `Handoff (${n}) ↗` : "Handoff ↗";
}

/* ---------------- rail: feed item detail ---------------- */
export function renderItem(rail, item, onEntity) {
  const url = safeUrl(item.url);
  const ents = Object.entries(item.entities || {})
    .flatMap(([k, vs]) => (vs || []).map(v => [k, v])).slice(0, 12);
  rail.innerHTML = `
    <div class="rail-h">
      <span class="caps cat-${esc(item.category)}">${esc(item.category)}</span>
      <span class="caps tone-accent">${esc(rel(item.published_at))}</span>
    </div>
    <div class="rail-body">
      <div class="rail-title">${url
        ? `<a href="${url}" target="_blank" rel="noopener noreferrer">${esc(item.title)} ↗</a>`
        : esc(item.title)}</div>
      <p class="rail-text">${esc(item.summary)}</p>
      ${ents.length ? `<div class="vtags">${ents.map(([k, v]) =>
        `<button class="vtag tone-muted" data-ent="${esc(v)}">${esc(v)}</button>`).join("")}</div>` : ""}
    </div>
    <div class="meta"><div class="l">Source</div><div class="v">${esc(item.source)}</div></div>
    <div class="meta"><div class="l">Published</div><div class="v">${esc(day(item.published_at))}</div></div>
    <div class="meta"><div class="l">Analyst actions</div>
      <div class="actions">
        <button class="act" data-copy="defanged">Copy defanged</button>
        <button class="act" data-copy="raw">Copy raw</button>
        <button class="act" data-copy="blurb">Copy summary</button>
        <button class="act${state.notable[item.id] ? " on" : ""}" data-copy="notable">Flag notable</button>
      </div></div>`;

  rail.querySelectorAll("[data-ent]").forEach(b =>
    b.onclick = () => onEntity?.(b.dataset.ent));

  rail.querySelectorAll("[data-copy]").forEach(b => b.onclick = () => {
    const mode = b.dataset.copy, was = b.textContent;
    if (mode === "notable") {
      toggleNotable(item); b.classList.toggle("on"); updateHandoff(); return;
    }
    const defang = s => String(s).replace(/\./g, "[.]").replace(/^http/i, "hxxp");
    const text = mode === "raw" ? item.url
      : mode === "defanged" ? defang(item.url)
      : `${item.title}\n\n${item.summary}\n\nSource: ${item.source} (${day(item.published_at)})\nReference: ${defang(item.url)}\n\nOpen-source reporting; shared for awareness.`;
    copyToButton(b, text, was);
  });
}

/* ---------------- vulnerability triage ---------------- */
let vulnState = { rows: [], sort: "risk", dir: -1, limit: 100, kevOnly: false, wlOnly: false };

export function initVulns(data, onPick) {
  vulnState.rows = data.cves?.cves ?? [];

  $("#wlInput").addEventListener("keydown", e => {
    if (e.key !== "Enter" || !e.target.value.trim()) return;
    addWatch(e.target.value); e.target.value = ""; drawWatch(); renderVulns(onPick);
  });
  $("#kevOnly").onclick = e => {
    vulnState.kevOnly = !vulnState.kevOnly;
    e.currentTarget.classList.toggle("on", vulnState.kevOnly); renderVulns(onPick);
  };
  $("#wlOnly").onclick = e => {
    vulnState.wlOnly = !vulnState.wlOnly;
    e.currentTarget.classList.toggle("on", vulnState.wlOnly); renderVulns(onPick);
  };
  $$("#cveHead th[data-sort]").forEach(th => th.onclick = () => {
    const k = th.dataset.sort;
    vulnState.dir = vulnState.sort === k ? -vulnState.dir : -1;
    vulnState.sort = k; renderVulns(onPick);
  });
  drawWatch();
  renderVulns(onPick);
}

function drawWatch() {
  $("#wlChips").innerHTML = state.watchlist.map(t =>
    `<span class="wlchip">${esc(t)}<button data-rm="${esc(t)}" aria-label="Remove">×</button></span>`).join("");
  $$("#wlChips [data-rm]").forEach(b => b.onclick = () => {
    removeWatch(b.dataset.rm); drawWatch(); renderVulns();
  });
}

function riskKey(c) { return (c.kev ? 2 : 0) + (c.epss ?? 0); }

function renderVulns(onPick) {
  let rows = vulnState.rows;
  if (vulnState.kevOnly) rows = rows.filter(c => c.kev);
  if (vulnState.wlOnly && state.watchlist.length)
    rows = rows.filter(c => watchHit([...(c.vendors ?? []), ...(c.products ?? [])]));

  const key = { risk: riskKey, cvss: c => c.cvss ?? -1, epss: c => c.epss ?? -1,
                cve: c => c.cve, published: c => c.published_at || "" }[vulnState.sort] || riskKey;
  rows = [...rows].sort((a, b) => {
    const x = key(a), y = key(b);
    return (x > y ? 1 : x < y ? -1 : 0) * vulnState.dir;
  });

  const shown = rows.slice(0, vulnState.limit);
  $("#cveRows").innerHTML = shown.map(c => {
    const sev = (c.cvss_severity || "").toLowerCase() || "unknown";
    const hit = watchHit([...(c.vendors ?? []), ...(c.products ?? [])]);
    return `<tr data-cve="${esc(c.cve)}">
      <td class="mono">${esc(c.cve)}</td>
      <td><span class="sev sev-${esc(sev)}">${esc(sev)}</span></td>
      <td class="mono r">${esc(c.cvss ?? "—")}</td>
      <td class="mono r">${c.epss != null ? Math.round(c.epss * 100) + "%" : "—"}</td>
      <td>${c.kev ? `<span class="kev">KEV${c.kev_ransomware ? "·R" : ""}</span>` : `<span class="sev-unknown">—</span>`}</td>
      <td>${esc([c.products?.[0], c.vendors?.[0]].filter(Boolean).join(" / ") || "—")}
          ${hit ? `<span class="wl">${esc(hit)}</span>` : ""}</td>
      <td class="mono r sev-unknown">${esc(day(c.published_at))}</td>
    </tr>`;
  }).join("");

  $("#cveCount").textContent = `${num(rows.length)} tracked`;
  $("#showMore").hidden = rows.length <= vulnState.limit;
  $("#showMore").onclick = () => { vulnState.limit += 100; renderVulns(onPick); };
  $$("#cveRows tr").forEach(tr => tr.onclick = () => onPick?.(tr.dataset.cve));
}

/* ---------------- trends: what CHANGED ---------------- */
/**
 * The static tier's answer to "what moved this week". Derived from committed
 * daily snapshots — git is the datastore, no backend involved.
 */
export function renderTrends(trends, onPick) {
  const box = $("#trends");
  if (!box) return;
  if (!trends || (!trends.epss_movers?.length && !trends.new_kev?.length)) {
    box.innerHTML = `<div class="trend-empty sev-unknown">Trend history builds
      from daily snapshots — comparisons appear after the second day of
      collection.</div>`;
    return;
  }
  const pct = n => Math.round((n ?? 0) * 100) + "%";
  const movers = (trends.epss_movers ?? []).slice(0, 5).map(m => `
    <button class="trend-row" data-cve="${esc(m.cve)}">
      <span class="mono${m.kev ? " tone-mark" : ""}">${esc(m.cve)}</span>
      <span class="trend-jump mono">${esc(pct(m.from))} → <b>${esc(pct(m.to))}</b></span>
      <span class="trend-delta mono sev-critical">▲ ${esc(pct(m.delta))}</span>
      <span class="trend-prod sev-unknown">${esc(m.product || "")}</span>
    </button>`).join("");
  const fresh = (trends.new_kev ?? []).slice(0, 5).map(k => `
    <button class="trend-row" data-cve="${esc(k.cve)}">
      <span class="mono tone-mark">${esc(k.cve)}</span>
      <span class="trend-jump mono">${k.epss != null ? esc(pct(k.epss)) : "—"}</span>
      <span class="trend-delta mono tone-mark">NEW KEV</span>
      <span class="trend-prod sev-unknown">${esc(k.product || "")}</span>
    </button>`).join("");
  const since = trends.totals?.compared_to
    ? `since ${esc(trends.totals.compared_to)}` : "";
  box.innerHTML = `
    <div class="trend-col">
      <div class="trend-h">Biggest exploitation-probability rises <span class="sev-unknown">${since}</span></div>
      ${movers || `<div class="trend-empty sev-unknown">No material movement.</div>`}
    </div>
    <div class="trend-col">
      <div class="trend-h">Newly added to CISA KEV <span class="sev-unknown">${since}</span></div>
      ${fresh || `<div class="trend-empty sev-unknown">No new entries.</div>`}
    </div>`;
  box.querySelectorAll("[data-cve]").forEach(b =>
    b.onclick = () => onPick?.(b.dataset.cve));
}

/* ---------------- brief / health / registry ---------------- */
export function renderBrief(brief) {
  const list = $("#briefList");
  if (!brief) {
    $("#briefGenerated").textContent = "not yet published";
    list.innerHTML = `<div class="bitem"><span class="bnum">—</span>
      <div><h3>No brief published yet</h3>
      <p>The daily brief is written on local hardware twice a day and ships
      independently of raw collection — feed freshness is unaffected.</p></div>
      <div></div></div>`;
    return;
  }
  $("#briefGenerated").textContent = `${brief.generated_at} · ${rel(brief.generated_at)}`;
  list.innerHTML = (brief.stories ?? []).map((s, n) => `
    <div class="bitem reveal" data-i="${n}">
      <span class="bnum">B${n + 1}</span>
      <div><h3>${esc(s.title)}</h3><p>${esc(s.summary)}</p></div>
      <div class="why"><div class="l">Why it matters</div><p>${esc(s.why_it_matters || "")}</p></div>
    </div>`).join("");
}

export function renderHealth(health) {
  const sources = health?.sources ?? [];
  $("#healthGrid").innerHTML = sources.map((s, n) => `
    <div class="hcell reveal" data-i="${n % 3}">
      <div class="hh"><span>${esc(s.source)}</span>
        <span class="dot${s.ok ? "" : " deg"}"></span></div>
      <div class="n${s.ok ? "" : " sev-medium"}" data-count="${esc(s.items)}">0</div>
      <div class="m">LAST OK · ${esc(s.last_success_at ? rel(s.last_success_at) : "NEVER")}</div>
      ${s.ok ? "" : `<div class="m sev-medium">${esc((s.error || "").slice(0, 80))}</div>`}
    </div>`).join("");
  $$("#healthGrid [data-count]").forEach(el =>
    onEnter(el, () => countUp(el, +el.dataset.count)));
  const warn = health?.pipeline_warnings;
  $("#healthWarn").innerHTML = warn?.length
    ? `<div class="warnstrip">${esc(warn.join(" · "))}</div>` : "";
}

export function renderRegistry(sources) {
  const rows = sources?.sources ?? [];
  $("#regRows").innerHTML = rows.map(s => `
    <tr><td>${esc(s.name)}</td>
    <td><span class="sev ${s.kind === "collector" ? "tone-accent" : "sev-unknown"}">${esc(s.kind)}</span></td>
    <td class="sev-unknown">${esc(s.coverage)}</td>
    <td class="mono r">${safeUrl(s.url)
      ? `<a class="tone-accent" href="${safeUrl(s.url)}" target="_blank" rel="noopener noreferrer">OPEN ↗</a>`
      : "—"}</td></tr>`).join("");
  $("#regCollectors").textContent = rows.filter(s => s.kind === "collector").length;
  $("#regReference").textContent = rows.filter(s => s.kind === "reference").length;
}
