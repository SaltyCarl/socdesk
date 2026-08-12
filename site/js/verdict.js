// verdict.js — indicator lookup, type-aware pivots, and the escalation card.
//
// AGGREGATOR MODEL (see COMPLIANCE.md): the only corpus we hold is the
// KEV/NVD/EPSS join, which is clearly redistributable. Reputation services are
// reached by USER-CLICKED deep links only — never fetched, never mirrored.
// Consequence: a CVE gets an authoritative verdict; every other indicator type
// gets an honest ROUTER verdict (type + escalation scaffold + pivots).
import { esc, safeUrl, detectType, refang, day, copyToButton } from "./data.js";
import { pushHistory } from "./state.js";

export function buildIndex(data) {
  const idx = { cve: new Map(), name: new Map() };
  for (const c of data.cves?.cves ?? []) idx.cve.set(c.cve.toUpperCase(), c);
  for (const kind of ["actors", "malware"])
    for (const p of data[kind]?.profiles ?? [])
      for (const n of [p.name, ...(p.aliases ?? [])])
        if (n) idx.name.set(String(n).toLowerCase(), { ...p, kind });
  return idx;
}

const enc = encodeURIComponent;

/** Type-aware external pivots. Links only — clicking discloses to that service. */
export function pivotsFor(type, q) {
  // Deliberately short. The tool serves one workflow — IP/hash into
  // AbuseIPDB/VirusTotal, URL into a safe viewer, screenshot, escalate —
  // so each type offers exactly the services that workflow uses. Vendors an
  // L1/L2 does not open on shift (Shodan, Censys, Spamhaus, sandboxes for
  // URL triage) were removed on purpose; do not accrete them back.
  const all = [
    ["VirusTotal", `https://www.virustotal.com/gui/search/${enc(q)}`],
  ];
  const add = rows => all.push(...rows);
  if (type === "ipv4") add([
    ["AbuseIPDB", `https://www.abuseipdb.com/check/${enc(q)}`],
    ["GreyNoise", `https://viz.greynoise.io/ip/${enc(q)}`],
  ]);
  if (type === "domain") add([
    ["urlscan", `https://urlscan.io/domain/${enc(q)}`],
  ]);
  if (type === "url") add([
    // Existing public scans first — inspecting someone else's completed scan
    // discloses nothing new. Browserling opens a LIVE remote browser at the
    // URL (active fetch = disclosure), hence the ⚠ convention.
    ["urlscan", `https://urlscan.io/search/#${enc(q)}`],
    ["Browserling ⚠", `https://www.browserling.com/browse/win/chrome/${enc(q)}`],
  ]);
  if (type === "md5" || type === "sha1" || type === "sha256") add([
    ["MalwareBazaar", `https://bazaar.abuse.ch/browse.php?search=${enc(q)}`],
  ]);
  if (type === "cve") add([
    ["NVD", `https://nvd.nist.gov/vuln/detail/${enc(q)}`],
    ["CISA KEV", `https://www.cisa.gov/known-exploited-vulnerabilities-catalog`],
    ["EPSS", `https://api.first.org/data/v1/epss?cve=${enc(q)}`],
  ]);
  if (type === "email") {
    all.length = 0;                       // no file/URL reputation for an email
    add([
      ["Have I Been Pwned", `https://haveibeenpwned.com/account/${enc(q)}`],
      ["Hudson Rock", `https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email=${enc(q)}`],
    ]);
  }
  return all.filter(([, u]) => safeUrl(u));
}

const miss = (q, type, note) => ({
  kind: "router", q, type: (type || "indicator").toUpperCase(), score: null,
  word: "NOT IN CORPUS", tone: "muted", basis: note ||
    "SOCDESK holds no reputation corpus for this indicator type by design — " +
    "reputation lives with the services below. Absence here is not clearance.",
  evidence: [],
});

export function verdict(raw, idx) {
  const q = refang(raw);
  if (!q) return null;
  const type = detectType(q);

  if (type === "cve") {
    const c = idx.cve.get(q.toUpperCase());
    if (!c) return { ...miss(q, "cve",
      "Not in the current 180-day window of the KEV/NVD/EPSS join. " +
      "Check NVD directly for older or reserved identifiers."), q };
    const epssPct = c.epss != null ? Math.round(c.epss * 100) : null;
    const word = c.kev ? "ACTIVELY EXPLOITED"
      : (c.epss ?? 0) >= .5 ? "LIKELY EXPLOITED"
      : (c.cvss ?? 0) >= 9 ? "CRITICAL SEVERITY" : "TRACKED";
    const tone = c.kev ? "red" : (c.epss ?? 0) >= .5 ? "orange"
      : (c.cvss ?? 0) >= 9 ? "orange" : "muted";
    const evidence = [
      ["CISA KEV", c.kev ? `listed ${c.kev_date_added}${c.kev_ransomware ? " · ransomware use known" : ""}` : "not listed"],
      ["CVSS", c.cvss != null ? `${c.cvss} ${c.cvss_severity || ""}`.trim() : "—"],
      ["EPSS", epssPct != null
        ? `${epssPct}% probability${c.epss_percentile != null ? ` · P${Math.round(c.epss_percentile * 100)}` : ""}`
        : "—"],
      ["Vendor / product", [c.vendors?.[0], c.products?.[0]].filter(Boolean).join(" / ") || "—"],
      ["Published", day(c.published_at)],
    ];
    return { kind: "cve", q: c.cve, type: "CVE", score: epssPct, word, tone, row: c,
      basis: c.kev
        ? "CISA has confirmed exploitation in the wild; treat exposed instances as urgent."
        : "Scored from public vulnerability data; not confirmed exploited.",
      evidence };
  }

  const prof = idx.name.get(q.toLowerCase());
  if (prof) return { kind: "profile", q, row: prof };

  if (!type) return { ...miss(q, "", "Unrecognised indicator format. Supported: IPv4, domain, URL, MD5/SHA-1/SHA-256, CVE, email."), q };
  return miss(q, type);
}

/* ------------------------------------------------------------------ *
 * Escalation card — the artifact that travels into a ticket.
 * GENERIC TEST (COMPLIANCE.md R6): any analyst at any company must be able
 * to paste this unchanged, and it must reveal nothing about how one specific
 * employer notifies its clients. Authored from scratch; deliberately NOT a
 * copy of any organisation's notification template, severity taxonomy or SLA
 * language.
 * ------------------------------------------------------------------ */
export function escalation(v, { markdown = true } = {}) {
  if (!v) return "";
  const stamp = new Date().toISOString().replace("T", " ").slice(0, 16) + "Z";
  const defanged = String(v.q).replace(/\./g, "[.]").replace(/^http/i, "hxxp");
  const b = markdown ? "**" : "";
  const lines = [
    `${markdown ? "## " : ""}INDICATOR REVIEW — ${defanged}`,
    "",
    `${b}Type${b}: ${v.type}`,
    `${b}Assessment${b}: ${v.word}${v.score != null ? ` (EPSS ${v.score}%)` : ""}`,
    `${b}Basis${b}: ${v.basis}`,
    "",
  ];
  if (v.evidence?.length) {
    lines.push(`${markdown ? "### " : ""}Public data`);
    for (const [k, val] of v.evidence) lines.push(`- ${b}${k}${b}: ${val}`);
    lines.push("");
  }
  lines.push(`${markdown ? "### " : ""}Suggested next steps`);
  for (const s of nextSteps(v)) lines.push(`- ${s}`);
  lines.push("", `${markdown ? "### " : ""}External references`);
  for (const [name, url] of pivotsFor(v.type.toLowerCase(), v.q))
    lines.push(markdown ? `- [${name}](${url})` : `- ${name}: ${url}`);
  lines.push("",
    `Reviewed ${stamp} · sources: CISA KEV, NVD, FIRST EPSS (public data).`,
    "Open-source assessment only — verify independently before acting.");
  return lines.join("\n");
}

function nextSteps(v) {
  const t = v.type.toLowerCase();
  if (t === "cve") {
    const s = ["Identify exposed instances of the affected product in scope.",
               "Confirm patch availability and apply per change process."];
    if (v.row?.kev) s.unshift("Prioritise: confirmed exploited in the wild (CISA KEV).");
    if (v.row?.kev_ransomware) s.push("Known ransomware campaign use — review backup and segmentation posture.");
    s.push("Hunt for exploitation attempts in perimeter and application logs.");
    return s;
  }
  if (t === "ipv4") return [
    "Search perimeter, proxy and firewall logs for traffic to or from this address.",
    "Check the external references below for current reputation and scan activity.",
    "Consider whether the address is shared infrastructure (CDN, VPN, CGNAT) before blocking.",
  ];
  if (t === "domain" || t === "url") return [
    "Search DNS, proxy and mail logs for resolution or access.",
    "Never browse it directly — check for an existing public scan first, and " +
      "detonate in a sandbox only if none exists.",
    "Check registration age and hosting in the external references below.",
  ];
  if (t.startsWith("sha") || t === "md5") return [
    "Search EDR telemetry for the hash across managed endpoints.",
    "Retrieve sandbox behaviour from the external references before drawing conclusions.",
    "If present, capture parent process and delivery path for the timeline.",
  ];
  if (t === "email") return [
    "Confirm whether the address appears in credential-exposure sources below.",
    "If a user account, review recent authentication events for that identity.",
    "Treat exposure as a password-reset and MFA-review trigger, not proof of compromise.",
  ];
  return ["Corroborate with the external references below before acting."];
}

/* ---------------- bulk mode ---------------- */
export function splitIndicators(text) {
  return [...new Set(String(text || "")
    .split(/[\s,;|]+/).map(refang).filter(s => s && detectType(s)))].slice(0, 200);
}

export function bulkRows(list, idx) {
  return list.map(q => {
    const v = verdict(q, idx);
    return { q, type: v?.type ?? "—", word: v?.word ?? "—",
             tone: v?.tone ?? "muted", score: v?.score ?? "" };
  });
}

export function toCSV(rows) {
  const cell = s => `"${String(s ?? "").replace(/"/g, '""')}"`;
  return ["indicator,type,assessment,score",
    ...rows.map(r => [r.q, r.type, r.word, r.score].map(cell).join(","))].join("\n");
}

export const toDefangedTxt = rows =>
  rows.map(r => `${String(r.q).replace(/\./g, "[.]")}\t${r.type}\t${r.word}`).join("\n");

export function download(name, text, mime = "text/plain") {
  const url = URL.createObjectURL(new Blob([text], { type: mime }));
  const a = document.createElement("a");
  a.href = url; a.download = name; a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/* ---------------- rendering: the verdict console ---------------- */
export const defangText = s =>
  String(s).replace(/\./g, "[.]").replace(/^http/i, "hxxp");

/** Escalation docket slip — the SAME content escalation() copies, rendered as
 *  a formatted document instead of raw markdown. What renders is what ships.
 *  Exported so the live-enrichment layer can re-render the slip with the
 *  multi-source verdict once /api/enrich answers. */
export function docketHTML(v) {
  const stamp = new Date().toISOString().replace("T", " ").slice(0, 16) + "Z";
  const pub = v.evidence?.length ? `
    <div class="dk-sec">Public data</div>
    ${v.evidence.map(([k, val]) => `<div class="dk-row">
      <span class="l">${esc(k)}</span><span class="v">${esc(val)}</span></div>`).join("")}` : "";
  const steps = nextSteps(v).map(s => `<li>${esc(s)}</li>`).join("");
  const refs = pivotsFor(v.type.toLowerCase(), v.q).map(([n]) => esc(n)).join(" · ");
  return `
    <div class="dk-title">INDICATOR REVIEW — ${esc(defangText(v.q))}</div>
    <div class="dk-row"><span class="l">Type</span><span class="v">${esc(v.type)}</span></div>
    <div class="dk-row"><span class="l">Assessment</span>
      <span class="v tone-${esc(v.tone)}">${esc(v.word)}${v.score != null ? ` (EPSS ${esc(v.score)}%)` : ""}</span></div>
    <div class="dk-row"><span class="l">Basis</span><span class="v">${esc(v.basis)}</span></div>
    ${pub}
    <div class="dk-sec">Suggested next steps</div>
    <ul class="dk-list">${steps}</ul>
    <div class="dk-sec">External references</div>
    <div class="dk-foot">${refs}</div>
    <div class="dk-foot">Reviewed ${esc(stamp)} · sources: CISA KEV, NVD, FIRST EPSS
      (public data). Open-source assessment only — verify independently before acting.</div>`;
}

export function renderVerdict(el, v, onDone) {
  if (!el || !v) return;
  if (v.kind === "profile") return;                 // profiles render elsewhere
  pushHistory(v.q, v.type, v.word);

  const pivots = pivotsFor(v.type.toLowerCase(), v.q).map(([n, u]) =>
    `<a class="pivot" href="${safeUrl(u)}" target="_blank" rel="noopener noreferrer">${esc(n)} ↗</a>`
  ).join("");
  // The verdict RADAR (the decided graphic — design/mockups/
  // verdict-graphic-radar-round2.html §A "Core") sits where the score donut
  // used to. It is a filled 5-axis profile (KEV · EPSS · CVSS · ransomware ·
  // recency) on a faceted hex plate carrying, as its bold centre number, the
  // SAME score verdict.js already computes — the VISUAL changed, the scoring did
  // not. Only a CVE carries the signals to plot; a router/miss keeps a clean
  // word-only head. The Public-data evidence stays owned by the escalation
  // summary on the right, so the left column reads clean: radar, indicator, basis.
  const gaugeBlock = v.kind === "cve" ? radarSVG(v) : "";

  el.innerHTML = `
    <div class="vc-head">
      <span class="caps tone-${esc(v.tone)}">Verdict · ${esc(v.type)}</span>
      <button class="act" data-vc="clear">Clear · Esc</button>
    </div>
    <div class="vc-grid">
      <div class="vc-main">
        <div class="gauge-wrap">${gaugeBlock}
          <div>
            <div class="verdict-word tone-${esc(v.tone)}" id="vword"></div>
          </div>
        </div>
        <div class="mono vc-ind" id="vq">${esc(defangText(v.q))}</div>
        <p class="vc-basis">${esc(v.basis)}</p>
      </div>
      <div class="vc-side esc">
        <div class="esc-h"><span class="cap">Intelligence summary</span>
          <span class="esc-acts">
            <button class="act" data-esc="md">Copy markdown</button>
            <button class="act" data-esc="txt">Copy text</button>
            <button class="act" data-esc="dl">Download .md</button>
          </span></div>
        <div class="docket" id="escBody">${docketHTML(v)}</div>
      </div>
    </div>
    <div class="ev"><div class="l">Pivot to — discloses this indicator to that service</div></div>
    <div class="pivots">${pivots}</div>`;

  el.querySelectorAll("[data-esc]").forEach(b => b.onclick = () => {
    const mode = b.dataset.esc, was = b.textContent;
    const text = escalation(v, { markdown: mode !== "txt" });
    if (mode === "dl") return download(`escalation-${v.q}.md`, text, "text/markdown");
    copyToButton(b, text, was);
  });
  el.querySelectorAll(".r2-corenum.count").forEach(runCount);   // score count-up (RM → final)
  onDone?.(el, v);
}

/* ================================================================== *
 * Consensus tally — the live-reputation language (docs/VERDICT-LANGUAGE.md).
 *
 * SOCDesk emits NO verdict word of its own for a live indicator. It counts what
 * independent public sources reported and shows each source's attributed
 * finding. These helpers are the single source of that wording on the site; the
 * browser extension carries a byte-identical copy, keyed off the SAME contract
 * and the SAME spec (never off this file). Change the spec, then change both.
 * ================================================================== */

/** tone (red|amber|green|grey) → the CSS tone class. amber uses the orange ink;
 *  grey uses muted (design law: gray = unknown, and it is never green). */
export const toneClass = tone =>
  ({ red: "red", amber: "orange", green: "green", grey: "muted" }[tone] ?? "muted");

/** The gauge headline (§2). Reads off the ratio, states green is not a
 *  clearance, states grey is not evidence of safety. */
export function tallyHeadline(flagged, consulted) {
  if (consulted === 0)
    return "No reputation data available from consulted sources. Not evidence of safety.";
  if (flagged === 0)
    return `0 of ${consulted} consulted sources flagged this — no adverse findings. Not a clearance.`;
  return `${flagged} of ${consulted} consulted sources flagged this as adverse.`;
}

/** The escalation ASSESSMENT line (§4). Deliberately worded "public reputation
 *  sources" (the card travels into a ticket), distinct from the gauge headline. */
export function assessmentLine(flagged, consulted) {
  if (consulted === 0)
    return "No reputation data available from consulted sources — not evidence of safety.";
  return `${flagged} of ${consulted} public reputation sources flagged this as adverse.`;
}

const stampUTC = d => new Date(d).toISOString().replace("T", " ").slice(0, 16) + " UTC";

/** The §4 escalation block as an ordered list of lines. Rendered to text (copy)
 *  and to HTML (the on-screen docket) from the SAME array, so what the analyst
 *  reads and what they paste can never drift apart. */
function tallyLines(result, now = new Date()) {
  const type = String(result.type ?? "").toUpperCase();
  const rows = Array.isArray(result.sources) ? result.sources : [];
  const scored = rows.filter(s => s.kind !== "context");
  const context = rows.filter(s => s.kind === "context");
  const errors = Array.isArray(result.errors) ? result.errors : [];

  const lines = [
    `INDICATOR: ${defangText(result.indicator)}  (${type})`,
    `ASSESSMENT: ${assessmentLine(result.flagged ?? 0, result.consulted ?? 0)}`,
    "",
    "EVIDENCE (third-party reputation data — attributed, not independently verified):",
    ...(scored.length
      ? scored.map(s => `  • ${s.name} — ${s.headline ?? "no finding reported"}`)
      : ["  • No consulted source returned a finding."]),
  ];

  if (context.length || errors.length) {
    lines.push("", "CONTEXT (not a verdict):");
    for (const c of context) lines.push(`  • ${c.name} — ${c.headline ?? "—"}`);
    if (errors.length)
      lines.push(`  • Not consulted: ${errors.map(e => `${e.source} (${e.reason})`).join(", ")}`);
  }

  lines.push(
    "",
    "CAVEAT: Reflects third-party reputation gathered at the time shown; it may be " +
      "incomplete or out of date and has not been independently confirmed.",
    `— Generated ${stampUTC(now)}. Sources queried ${stampUTC(result.checked_at ?? now)}.`,
  );
  return lines;
}

/** The copy-to-clipboard / download escalation text (§4). */
export function tallyEscalation(result, now = new Date()) {
  return tallyLines(result, now).join("\n");
}

/** The on-screen escalation docket — the identical lines, escaped, one per div
 *  so the rendered summary equals the copied text verbatim. Not a <pre>. */
export function tallyDocketHTML(result, now = new Date()) {
  return tallyLines(result, now)
    .map(line => line === ""
      ? `<div class="dk-gap"></div>`
      : `<div class="dk-line">${esc(line)}</div>`)
    .join("");
}

/* ================================================================== *
 * Verdict RADAR — the decided score graphic (the "Core" treatment in
 * design/mockups/verdict-graphic-radar-round2.html §A). A filled 5-axis profile
 * on a faceted hex plate with a bold central number.
 *
 * CSP LAW (style-src 'self' blocks inline style="" — the mockup's technique
 * does NOT carry over): every element is coloured by SVG PRESENTATION ATTRIBUTES
 * (fill/stroke/opacity/…) and CSS CLASSES only. The reserved verdict tone
 * (red/amber/green by severity) rides as `color` on the .radar root via the
 * shipped `tone-*` classes, and the profile inherits it through
 * fill/stroke="currentColor" — the same currentColor trick the old gauge used.
 * Frame strokes (rings/spokes/ticks/plate) stay warm-neutral. No external
 * requests. The grow-in draw and the centre count-up degrade to their final
 * state under prefers-reduced-motion (CSS gate + runCount below).
 * ================================================================== */
const RAD = { cx: 105, cy: 100, R: 66, rings: 3, stroke: 1.8, dot: 3, fillOp: 0.18, plate: 26 };

const polar = (cx, cy, r, deg) => {
  const a = (deg - 90) * Math.PI / 180;
  return [cx + r * Math.cos(a), cy + r * Math.sin(a)];
};

const prefersReduced = () =>
  typeof matchMedia === "function" && matchMedia("(prefers-reduced-motion: reduce)").matches;

/** Reveal the true centre value by counting up to it; reduced-motion lands on
 *  the final value instantly. Writes textContent only — no style, CSP-clean. */
function runCount(node) {
  const to = parseInt(node.dataset.to, 10);
  if (!Number.isFinite(to)) return;
  if (prefersReduced() || typeof requestAnimationFrame !== "function") {
    node.textContent = String(to); return;
  }
  const dur = 750, t0 = performance.now();
  node.textContent = "0";
  const tick = now => {
    const p = Math.min(1, (now - t0) / dur), e = 1 - Math.pow(1 - p, 3);
    node.textContent = String(Math.round(e * to));
    if (p < 1) requestAnimationFrame(tick); else node.textContent = String(to);
  };
  requestAnimationFrame(tick);
}

/** The 5 fixed axes, built from the SAME CVE row the verdict is scored from.
 *  KEV and RANSOM are yes/no (a rim diamond marks a confirmed one); EPSS/CVSS
 *  scale 0–100; RECENCY decays from the publish date over ~2 years. Values are
 *  read straight off public data — nothing is invented. */
function cveAxes(row, score) {
  const epssPct = score != null ? score
    : (row.epss != null ? Math.round(row.epss * 100) : null);
  const cvss = row.cvss != null ? Number(row.cvss) : null;
  const pub = row.published_at ? Date.parse(row.published_at) : NaN;
  const ageDays = Number.isFinite(pub) ? (Date.now() - pub) / 864e5 : null;
  const recV = ageDays == null ? 45
    : Math.max(0, Math.min(100, Math.round(100 * (1 - ageDays / 1095))));     // linear decay over ~3yr
  const recRaw = ageDays == null ? "n/a"
    : ageDays < 60 ? "recent" : ageDays < 180 ? "3mo"
    : ageDays < 365 ? "this yr" : String(new Date(pub).getUTCFullYear());
  return [
    { k: "KEV",     v: row.kev ? 100 : 0,                       raw: row.kev ? "confirmed" : "none",       binary: !!row.kev },
    { k: "EPSS",    v: epssPct != null ? epssPct : 0,           raw: epssPct != null ? epssPct + "%" : "—", binary: false },
    { k: "CVSS",    v: cvss != null ? Math.round(cvss * 10) : 0, raw: cvss != null ? String(cvss) : "—",    binary: false },
    { k: "RANSOM",  v: row.kev_ransomware ? 100 : 0,            raw: row.kev_ransomware ? "known" : "none", binary: !!row.kev_ransomware },
    { k: "RECENCY", v: recV,                                    raw: recRaw,                               binary: false },
  ];
}

function radarSVG(v) {
  const { cx, cy, R } = RAD;
  const A = cveAxes(v.row, v.score), N = A.length, step = 360 / N;
  let g = "";

  // concentric rings + rim bearing ticks (warm neutral, faint)
  for (let i = 1; i <= RAD.rings; i++)
    g += `<circle class="r2-ring" cx="${cx}" cy="${cy}" r="${(R * i / RAD.rings).toFixed(1)}" opacity="${(0.26 + 0.2 * i / RAD.rings).toFixed(2)}"/>`;
  for (let d = 0; d < 360; d += 15) {
    const [ox, oy] = polar(cx, cy, R, d), [ix, iy] = polar(cx, cy, R - (d % 45 === 0 ? 5 : 3), d);
    g += `<line class="r2-tick" x1="${ox.toFixed(1)}" y1="${oy.toFixed(1)}" x2="${ix.toFixed(1)}" y2="${iy.toFixed(1)}" opacity="${d % 45 === 0 ? .5 : .3}"/>`;
  }

  // spokes + axis labels
  A.forEach((s, i) => {
    const [sx, sy] = polar(cx, cy, R, i * step);
    g += `<line class="r2-spoke" x1="${cx}" y1="${cy}" x2="${sx.toFixed(1)}" y2="${sy.toFixed(1)}" opacity="0.4"/>`;
    const [lx, ly] = polar(cx, cy, R + 15, i * step);
    const anchor = lx < cx - 2 ? "end" : lx > cx + 2 ? "start" : "middle";
    g += `<text class="r2-axlabel" x="${lx.toFixed(1)}" y="${ly.toFixed(1)}" text-anchor="${anchor}">${esc(s.k)}</text>`;
    g += `<text class="r2-axsub" x="${lx.toFixed(1)}" y="${(ly + 8).toFixed(1)}" text-anchor="${anchor}">${esc(s.raw)}</text>`;
  });

  // the data profile (tone via currentColor) — grouped so it grows in from centre
  const pts = A.map((s, i) => polar(cx, cy, R * Math.max(0, Math.min(100, s.v)) / 100, i * step));
  const dPoly = pts.map((p, i) => (i ? "L" : "M") + p[0].toFixed(1) + " " + p[1].toFixed(1)).join(" ") + " Z";
  let plot = `<path class="r2-poly" d="${dPoly}" fill="currentColor" fill-opacity="${RAD.fillOp}" stroke="currentColor" stroke-width="${RAD.stroke}"/>`;
  A.forEach((s, i) => {
    const [px, py] = pts[i];
    plot += `<circle class="r2-vtx" cx="${px.toFixed(1)}" cy="${py.toFixed(1)}" r="${RAD.dot}" fill="currentColor"/>`;
    if (s.binary) {                                    // a confirmed yes/no axis → a rim diamond
      const [bx, by] = polar(cx, cy, R, i * step);
      plot += `<rect class="r2-pip" x="${(bx - 3).toFixed(1)}" y="${(by - 3).toFixed(1)}" width="6" height="6" rx="1" fill="currentColor" transform="rotate(45 ${bx.toFixed(1)} ${by.toFixed(1)})"/>`;
    }
  });
  g += `<g class="r2-plot">${plot}</g>`;

  // faceted hex plate (never a ring gauge) + the score verdict.js already computed
  const plate = [];
  for (let k = 0; k < 6; k++) { const [hx, hy] = polar(cx, cy, RAD.plate, k * 60); plate.push(`${hx.toFixed(1)} ${hy.toFixed(1)}`); }
  g += `<polygon class="r2-plate" points="${plate.join(" ")}"/>`;
  if (v.score != null) {
    g += `<text class="r2-corenum count" data-to="${esc(String(v.score))}" x="${cx}" y="${cy + 2}" text-anchor="middle" fill="currentColor">${esc(String(v.score))}</text>`;
    g += `<text class="r2-coreunit" x="${cx}" y="${cy + 13}" text-anchor="middle">/100</text>`;
  } else {
    g += `<text class="r2-corenum" x="${cx}" y="${cy + 5}" text-anchor="middle" fill="currentColor">—</text>`;
  }

  const aria = `Verdict radar for ${v.q}: ${v.word}. ` + A.map(s => `${s.k} ${s.raw}`).join(", ") + ".";
  return `<svg class="radar tone-${v.tone}" viewBox="-16 -8 244 214" role="img" aria-label="${esc(aria)}">${g}</svg>`;
}
