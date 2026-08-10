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
  const ev = v.evidence?.length ? `<div class="ev"><div class="l">Public data</div>${
    v.evidence.map(([k, val]) =>
      `<div class="ev-row"><span class="k">${esc(k)}</span><span class="d">${esc(val)}</span></div>`
    ).join("")}</div>` : "";
  const gauge = v.score != null ? gaugeSVG(v.score, v.tone) : "";

  el.innerHTML = `
    <div class="vc-head">
      <span class="caps tone-${esc(v.tone)}">Verdict · ${esc(v.type)}</span>
      <button class="act" data-vc="clear">Clear · Esc</button>
    </div>
    <div class="vc-grid">
      <div class="vc-main">
        <div class="gauge-wrap">${gauge}
          <div>
            ${v.score != null ? `<div class="gauge-num tone-${esc(v.tone)}">${esc(v.score)}<span class="sev-unknown">/100</span></div>` : ""}
            <div class="verdict-word tone-${esc(v.tone)}" id="vword"></div>
          </div>
        </div>
        <div class="mono vc-ind" id="vq">${esc(defangText(v.q))}</div>
        <p class="vc-basis">${esc(v.basis)}</p>
      </div>
      <div class="vc-side esc">
        <div class="esc-h"><span class="cap">Escalation summary</span>
          <span class="esc-acts">
            <button class="act" data-esc="md">Copy markdown</button>
            <button class="act" data-esc="txt">Copy text</button>
            <button class="act" data-esc="dl">Download .md</button>
          </span></div>
        <div class="docket" id="escBody">${docketHTML(v)}</div>
      </div>
    </div>
    ${ev}
    <div class="ev"><div class="l">Pivot to — discloses this indicator to that service</div></div>
    <div class="pivots">${pivots}</div>`;

  el.querySelectorAll("[data-esc]").forEach(b => b.onclick = () => {
    const mode = b.dataset.esc, was = b.textContent;
    const text = escalation(v, { markdown: mode !== "txt" });
    if (mode === "dl") return download(`escalation-${v.q}.md`, text, "text/markdown");
    copyToButton(b, text, was);
  });
  onDone?.(el, v);
}

function gaugeSVG(score, tone) {
  const r = 42, c = 2 * Math.PI * r, off = c * (1 - Math.max(0, Math.min(100, score)) / 100);
  return `<svg class="gauge" viewBox="0 0 96 96" aria-hidden="true">
    <circle class="track" cx="48" cy="48" r="${r}"></circle>
    <circle class="arc tone-${tone}" cx="48" cy="48" r="${r}" stroke="currentColor"
      stroke-dasharray="${c}" stroke-dashoffset="${c}" data-off="${off}"
      transform="rotate(-90 48 48)"></circle>
  </svg>`;
}
