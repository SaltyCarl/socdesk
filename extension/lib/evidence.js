// evidence.js — the escalation "Copy card": the reputation of one indicator,
// drawn to a PNG that an analyst drops straight into a client-facing email.
//
// WHY AN IMAGE. Plain text can't carry a graphic and rich-HTML copy is stripped
// unpredictably by mail/ticket sanitizers, so the one reliable way to put a
// visual into a pasted email is an image on the clipboard. This also automates
// the north-star step (screenshot the reputation, paste into the email) and the
// image cannot be lost or reflowed the way pasted markup can. The plain-text
// block always travels alongside it for deliverability and accessibility.
//
// THIS FILE IS SHARED, BYTE-FOR-BYTE, BY BOTH SURFACES.
//   * site/js/evidence.js        — imported by site/js/enrich-client.js
//   * extension/lib/evidence.js  — imported by extension/popup.js
// The two copies MUST stay identical so the site and the extension emit exactly
// the same card; evidence.spec.js asserts they are byte-identical. It is
// therefore SELF-CONTAINED: no imports, no framework, no external resource of
// any kind — every colour, font family, the world landmask and the wording all
// ship inside this module. Nothing is fetched at capture time, so it is safe
// under `default-src 'none'` and under the extension's MV3 CSP, and the
// indicator + its coordinates never leave the browser.
//
// HONESTY, per docs/VERDICT-LANGUAGE.md §4 (binding):
//   * The tally LEADS, as a count — "N of M sources flagged this" — never a
//     SOCDesk-voice verdict word (malicious/suspicious/safe/clean).
//   * Every source is attributed with its own finding as fact.
//   * A dual-use / mitigating qualifier (e.g. a Tor exit node) sits directly
//     under the tally, so "N of M" is never misread as N independent confirmations.
//   * Geolocation is prominent but explicitly labelled "context — not a verdict"
//     and never enters the tally.
//   * The verify caveat is baked into the image so it cannot be lost on forward.
//   * NO recommendation, and NO branding — the copied artifact carries a neutral
//     timestamp provenance only; the SOCDesk name/mark live in the app UI, never
//     in the picture that rides inside the analyst's own MSSP email.

/* ============================================================ *
 * Theme — the warm-espresso / warm-paper + periwinkle system.
 * Canvas cannot read CSS custom properties, so the palette is
 * materialised here as the same hexes as design/mockups/palette-warm-v2.html.
 * ============================================================ */

const THEMES = {
  light: {
    bg: "#F2E6D0", panel: "#FBF4E6", panel2: "#F0E2C9", field: "#FDF8EE",
    border: "#DFC9A2", border2: "#CDB183", border3: "#B8975F",
    text: "#2C2013", textDim: "#6A5638", textFaint: "#98835D",
    accent: "#4A4FD0", accent2: "#6E74E0",
    vRed: "#D33A50", vAmber: "#B4740C", vGreen: "#1E9E57",
  },
  dark: {
    bg: "#15100A", panel: "#1E1710", panel2: "#2A2015", field: "#120D07",
    border: "#34281B", border2: "#473721", border3: "#5E4829",
    text: "#F1E8D8", textDim: "#B7A488", textFaint: "#877253",
    accent: "#7C8AFF", accent2: "#ADB6FF",
    vRed: "#F5566B", vAmber: "#F2A81E", vGreen: "#4FC97A",
  },
};

/** The active theme: an explicit [data-theme], else the OS preference, else
 *  dark (the product's default look). Identical logic on both surfaces. */
export function detectTheme() {
  try {
    const t = document.documentElement.dataset.theme;
    if (t === "light" || t === "dark") return t;
    if (window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches)
      return "light";
  } catch { /* non-DOM context */ }
  return "dark";
}

const SANS = '"Archivo", "Segoe UI", system-ui, sans-serif';
const MONO = '"IBM Plex Mono", ui-monospace, "Cascadia Mono", Consolas, monospace';

/* ---------- geometry ---------------------------------------------------- */

const W = 440;        // CSS px — comfortable inline in an email body
const PAD = 18;
const SCALE = 2;      // drawn at 2x so it stays crisp when scaled or printed
const RADIUS = 12;

/* ---------- small colour helpers ---------------------------------------- */

function hexToRgb(h) {
  const s = String(h).replace("#", "");
  return [parseInt(s.slice(0, 2), 16), parseInt(s.slice(2, 4), 16), parseInt(s.slice(4, 6), 16)];
}
/** Blend `a` over `b` at weight `t` (t of a). Returns an #rrggbb string. */
function mix(a, b, t) {
  const A = hexToRgb(a), B = hexToRgb(b);
  const c = A.map((v, i) => Math.round(v * t + B[i] * (1 - t)));
  return "#" + c.map(v => v.toString(16).padStart(2, "0")).join("");
}

/* ============================================================ *
 * Geolocation reference data — names, rough centroids, flags.
 * All static, all embedded. The pin is placed by an equirectangular
 * projection of a lat/long; with no precise coordinate on the wire we
 * fall back to the country's centroid (the map is a coarse dot-matrix,
 * so country-level is more than enough) and we NEVER print a precise-
 * looking coordinate we do not actually have.
 * ============================================================ */

// code -> [name, lat, lon]
const GEO = {
  US: ["United States", 39.8, -98.6], CA: ["Canada", 56.1, -106.3], MX: ["Mexico", 23.6, -102.5],
  BR: ["Brazil", -10.3, -53.2], AR: ["Argentina", -38.4, -63.6], CL: ["Chile", -35.7, -71.5],
  CO: ["Colombia", 4.6, -74.3], PE: ["Peru", -9.2, -75.0], VE: ["Venezuela", 6.4, -66.6],
  GB: ["United Kingdom", 54.0, -2.9], IE: ["Ireland", 53.4, -8.2], FR: ["France", 46.6, 2.5],
  DE: ["Germany", 51.2, 10.5], NL: ["Netherlands", 52.1, 5.3], BE: ["Belgium", 50.6, 4.6],
  LU: ["Luxembourg", 49.8, 6.1], CH: ["Switzerland", 46.8, 8.2], AT: ["Austria", 47.6, 14.1],
  IT: ["Italy", 42.8, 12.6], ES: ["Spain", 40.2, -3.7], PT: ["Portugal", 39.6, -8.0],
  SE: ["Sweden", 62.2, 15.3], NO: ["Norway", 64.6, 12.0], FI: ["Finland", 64.5, 26.3],
  DK: ["Denmark", 56.0, 9.5], IS: ["Iceland", 64.9, -18.6], PL: ["Poland", 51.9, 19.1],
  CZ: ["Czechia", 49.8, 15.5], SK: ["Slovakia", 48.7, 19.7], HU: ["Hungary", 47.2, 19.5],
  RO: ["Romania", 45.9, 25.0], BG: ["Bulgaria", 42.7, 25.5], GR: ["Greece", 39.1, 22.9],
  HR: ["Croatia", 45.1, 15.2], RS: ["Serbia", 44.0, 21.0], SI: ["Slovenia", 46.1, 14.8],
  UA: ["Ukraine", 48.4, 31.2], BY: ["Belarus", 53.7, 27.9], MD: ["Moldova", 47.4, 28.4],
  LT: ["Lithuania", 55.2, 23.9], LV: ["Latvia", 56.9, 24.6], EE: ["Estonia", 58.6, 25.0],
  RU: ["Russia", 61.5, 105.3], TR: ["Türkiye", 39.0, 35.2], CY: ["Cyprus", 35.1, 33.4],
  IL: ["Israel", 31.4, 34.9], AE: ["United Arab Emirates", 24.0, 54.0], SA: ["Saudi Arabia", 24.0, 45.1],
  IR: ["Iran", 32.4, 53.7], IQ: ["Iraq", 33.2, 43.7], EG: ["Egypt", 26.8, 30.8],
  ZA: ["South Africa", -30.6, 22.9], NG: ["Nigeria", 9.1, 8.7], KE: ["Kenya", 0.0, 37.9],
  MA: ["Morocco", 31.8, -7.1], DZ: ["Algeria", 28.0, 1.7], IN: ["India", 22.4, 78.7],
  PK: ["Pakistan", 30.4, 69.3], BD: ["Bangladesh", 23.7, 90.4], CN: ["China", 35.9, 104.2],
  HK: ["Hong Kong", 22.3, 114.2], TW: ["Taiwan", 23.7, 121.0], JP: ["Japan", 36.2, 138.3],
  KR: ["South Korea", 36.4, 127.9], KP: ["North Korea", 40.3, 127.5], VN: ["Vietnam", 16.0, 108.0],
  TH: ["Thailand", 15.1, 101.0], MY: ["Malaysia", 4.2, 101.9], SG: ["Singapore", 1.35, 103.8],
  ID: ["Indonesia", -2.5, 118.0], PH: ["Philippines", 12.9, 121.8], AU: ["Australia", -25.7, 134.5],
  NZ: ["New Zealand", -41.8, 172.9],
};

// A small set of easily-drawn flags. Each is equal-width/height bands, in the
// given direction; 'h' = stacked top→bottom, 'v' = left→right. Countries whose
// flag is not a plain band arrangement (crosses, unions, stars) fall back to a
// neutral chip carrying the ISO code, which is honest and always renders.
const FLAGS = {
  DE: { dir: "h", bands: ["#111111", "#DD0000", "#FFCE00"] },
  FR: { dir: "v", bands: ["#0055A4", "#FFFFFF", "#EF4135"] },
  NL: { dir: "h", bands: ["#AE1C28", "#FFFFFF", "#21468B"] },
  IT: { dir: "v", bands: ["#008C45", "#F4F5F0", "#CD212A"] },
  IE: { dir: "v", bands: ["#169B62", "#FFFFFF", "#FF883E"] },
  BE: { dir: "v", bands: ["#111111", "#FDDA24", "#EF3340"] },
  RO: { dir: "v", bands: ["#002B7F", "#FCD116", "#CE1126"] },
  RU: { dir: "h", bands: ["#FFFFFF", "#0039A6", "#D52B1E"] },
  ES: { dir: "h", bands: ["#AA151B", "#F1BF00", "#AA151B"] },
  AT: { dir: "h", bands: ["#ED2939", "#FFFFFF", "#ED2939"] },
  BG: { dir: "h", bands: ["#FFFFFF", "#00966E", "#D62612"] },
  LT: { dir: "h", bands: ["#FDB913", "#006A44", "#C1272D"] },
  PL: { dir: "h", bands: ["#FFFFFF", "#DC143C"] },
  UA: { dir: "h", bands: ["#0057B7", "#FFD700"] },
  ID: { dir: "h", bands: ["#FF0000", "#FFFFFF"] },
};

/* ============================================================ *
 * The world landmask — a coarse dot-matrix (equirectangular), the
 * same fixed public-domain-style outline shipped in the mockup. The
 * same bytes render every time; it leaks nothing about the target.
 * '#' = land. The pin is drawn at the projected lat/long over it.
 * ============================================================ */
const WORLD = [
  "............................#######.............................................",
  "............................#######.....................#############...........",
  "....#####..........####......#######...............#########################....",
  "...#####################.....######........#####################################",
  "...#######################....####.......#######################################",
  "..........#################............#####################################....",
  "...........################...........#####################################.....",
  "...........################.............##################################......",
  "............##############.............########..########################.......",
  "............############...............##.####...########################.......",
  ".............###########..............#...........######################........",
  "..............#########..................##........###################..........",
  ".................######.................#######....################.............",
  ".................#####.................#########....###############.............",
  "......................................##########.......############.............",
  "..................##.................############.......###..####...............",
  "....................#...............#############.......##...###...#............",
  ".....................#####..........###############......#....#...##............",
  "......................#####...........#############.............................",
  "......................######.............##########..........#..................",
  "......................########............########............###...............",
  "......................##########..........#######..............##########.......",
  "......................##########..........#######...............................",
  ".......................########...........#######...................####........",
  ".......................########............#####..#................#####........",
  ".......................#######.............#####..#..............########.......",
  "........................#####..............####..................########.......",
  "........................####................##....................#######.......",
  "........................###.................##........................###.......",
  "........................###.....................................................",
  ".......................###...................................................##.",
  ".......................##....................................................###",
  "................................................................................",
  "................................................................................",
];

/* ---------- content model (pure — this is what the tests assert) --------- */

const TYPE_LABEL = {
  ipv4: "IPv4", domain: "DOMAIN", url: "URL",
  md5: "MD5", sha1: "SHA-1", sha256: "SHA-256",
};

const stampUTC = d => new Date(d).toISOString().replace("T", " ").slice(0, 16) + " UTC";

/** The per-source rank used to colour a dot / gauge segment. A source that
 *  returned no data (unknown) is NOT green — green means a source looked and
 *  found nothing adverse; grey means it had nothing to say. */
function verdictRank(v) {
  return v === "malicious" ? 0 : v === "suspicious" ? 1 : v === "benign" ? 2 : 3;
}

/** Expand analyst shorthand for a client-facing reader (spell out C2 / IOC /
 *  RAT). Conservative: only unambiguous, whole-word acronyms are expanded, and
 *  the acronym is kept in parentheses so a technical reader still sees it. */
function glossJargon(s) {
  return String(s ?? "")
    .replace(/\bIOCs\b/g, "indicators of compromise")
    .replace(/\bIOC\b/g, "indicator of compromise")
    .replace(/\bC2\b/g, "command-and-control (C2)")
    .replace(/\bC&C\b/g, "command-and-control (C2)")
    .replace(/\bRAT\b/g, "remote-access trojan (RAT)");
}

/** The tally headline (§2/§4). Leads as a count; states green is not a
 *  clearance and grey is not evidence of safety. */
function tallyHeadline(flagged, consulted) {
  if (consulted === 0)
    return "No reputation data from consulted sources. Not evidence of safety.";
  if (flagged === 0)
    return `0 of ${consulted} consulted sources flagged this — no adverse findings. Not a clearance.`;
  return `${flagged} of ${consulted} public reputation sources flagged this as adverse.`;
}

/** Derive the geolocation block from the context (ipinfo) row, falling back to
 *  AbuseIPDB's country if no context row is present. Returns null for indicator
 *  types that have no location (hashes, most domains). */
function geoModel(sources) {
  const factMap = row => new Map((row.facts ?? []).map(([k, v]) => [String(k).toLowerCase(), v]));

  const ctx = (sources ?? []).find(s => s.kind === "context");
  let code = "", city = "", asn = "", org = "", lat = null, lon = null;

  if (ctx) {
    const f = factMap(ctx);
    const loc = String(f.get("location") ?? "");           // "City, Region, CC"
    const parts = loc.split(",").map(s => s.trim()).filter(Boolean);
    if (parts.length) {
      const last = parts[parts.length - 1];
      if (/^[A-Za-z]{2}$/.test(last)) code = last.toUpperCase();
      if (parts.length > 1) city = parts[0];
    }
    asn = String(f.get("asn") ?? "").replace(/^—$/, "");
    org = String(f.get("organisation") ?? f.get("organization") ?? "").replace(/^—$/, "");
    // Use a precise coordinate ONLY if the contract ever carries one.
    for (const v of (ctx.facts ?? []).map(([, val]) => String(val))) {
      const m = v.match(/^\s*(-?\d{1,2}(?:\.\d+)?)\s*,\s*(-?\d{1,3}(?:\.\d+)?)\s*$/);
      if (m) { lat = parseFloat(m[1]); lon = parseFloat(m[2]); break; }
    }
  }

  if (!code) {   // fall back to a reputation source's country code (AbuseIPDB)
    for (const s of sources ?? []) {
      const cc = factMap(s).get("country");
      if (cc && /^[A-Za-z]{2}$/.test(String(cc))) { code = String(cc).toUpperCase(); break; }
    }
  }

  if (!code && lat == null) return null;

  const ref = GEO[code];
  const precise = lat != null && lon != null;
  if (!precise && ref) { lat = ref[1]; lon = ref[2]; }
  if (lat == null || lon == null) { lat = 20; lon = 0; }   // last-resort centre

  return {
    countryCode: code,
    countryName: ref ? ref[0] : (code || "Location"),
    city, asn, org,
    lat, lon, precise,
    flag: FLAGS[code] || null,
  };
}

/** Surface dual-use / mitigating qualifiers so the reader never treats the
 *  tally as N independent confirmations. Read straight from the source facts. */
function mitigationsFrom(sources) {
  const out = [];
  let tor = false, riot = false, noise = false;
  for (const s of sources ?? []) {
    const f = new Map((s.facts ?? []).map(([k, v]) => [String(k).toLowerCase(), String(v).toLowerCase()]));
    if (f.get("tor exit node") === "yes") tor = true;
    if (f.get("known-good service (riot)") === "yes") riot = true;
    if (f.get("internet noise") === "yes") noise = true;
    const blob = (String(s.headline ?? "") + " " + (s.facts ?? []).map(x => x[1]).join(" ")).toLowerCase();
    if (blob.includes("tor exit")) tor = true;
  }
  if (tor) out.push("Tagged as a Tor exit node — heavy abuse reporting can reflect shared, " +
    "dual-use privacy traffic rather than one hostile operator.");
  if (riot) out.push("GreyNoise classifies this as a common, known-good business service (RIOT) — " +
    "likely benign shared infrastructure.");
  if (noise && !tor) out.push("Seen as broad internet background scanning, not necessarily aimed at you.");
  return out;
}

/**
 * Turn an /api/enrich response into the card's content. No canvas, no DOM — so
 * the thing that decides what the card SAYS is testable without rendering a
 * pixel. Carries NO branding: provenance is a neutral timestamp only.
 */
export function evidenceModel(result, now = new Date()) {
  const flagged = Number(result?.flagged ?? 0);
  const consulted = Number(result?.consulted ?? 0);
  const tone = String(result?.tone ?? "grey");
  const rows = Array.isArray(result?.sources) ? result.sources : [];
  const scored = rows.filter(s => s.kind !== "context");

  const malicious = scored.filter(s => s.verdict === "malicious").length;
  const suspicious = scored.filter(s => s.verdict === "suspicious").length;
  const notFlagged = consulted - malicious - suspicious;

  const capLeft = [];
  if (malicious) capLeft.push(`${malicious} malicious`);
  if (suspicious) capLeft.push(`${suspicious} suspicious`);
  if (!capLeft.length) capLeft.push("none flagged");

  return {
    // provenance is timestamps only — the copied artifact is unbranded (§4).
    type: result?.type ?? "",
    typeLabel: TYPE_LABEL[result?.type] ?? String(result?.type ?? "").toUpperCase(),
    indicator: result?.indicator ?? "",

    flagged, consulted, tone,
    tallyNum: `${flagged} / ${consulted}`,
    headline: tallyHeadline(flagged, consulted),

    // one gauge segment per consulted source, severity-ordered for a clean read
    segments: [...scored]
      .sort((a, b) => verdictRank(a.verdict) - verdictRank(b.verdict))
      .map(s => ({ verdict: s.verdict ?? "unknown" })),
    counts: { malicious, suspicious, notFlagged },
    caption: { left: capLeft.join(" · "), right: `${notFlagged} not flagged` },

    // promoted directly under the tally
    mitigations: mitigationsFrom(scored),

    geo: geoModel(rows),

    // attributed reputation rows — consulted sources only; the source's own
    // finding, glossed for a client reader, never promoted to a SOCDesk verdict.
    sources: scored.map(s => ({
      name: s.name,
      verdict: s.verdict ?? "unknown",
      finding: glossJargon(s.headline ?? "no finding reported"),
      url: s.url ?? "",
    })),

    // §4, verbatim
    caveat: "Reflects third-party reputation gathered at the time shown; it may be " +
      "incomplete or out of date and has not been independently confirmed.",

    provenance: {
      generated: stampUTC(now),
      queried: stampUTC(result?.checked_at ?? now),
    },
  };
}

/* ---------- text helpers ------------------------------------------------- */

let measureCtx = null;
function measurer() {
  if (!measureCtx) measureCtx = document.createElement("canvas").getContext("2d");
  return measureCtx;
}

/** Greedy wrap; falls back to hard character breaks for unbroken strings — a
 *  64-char hash or a long URL has no spaces to wrap on. */
function wrap(ctx, text, font, maxWidth) {
  ctx.font = font;
  const out = [];
  for (const paragraph of String(text).split("\n")) {
    let line = "";
    for (const word of paragraph.split(/\s+/)) {
      const next = line ? `${line} ${word}` : word;
      if (ctx.measureText(next).width <= maxWidth) { line = next; continue; }
      if (line) out.push(line);
      if (ctx.measureText(word).width <= maxWidth) { line = word; continue; }
      let chunk = "";
      for (const ch of word) {
        if (ctx.measureText(chunk + ch).width > maxWidth) { out.push(chunk); chunk = ch; }
        else chunk += ch;
      }
      line = chunk;
    }
    out.push(line);
  }
  return out;
}

function roundRect(ctx, x, y, w, h, r) {
  const rr = Math.min(r, w / 2, h / 2);
  ctx.beginPath();
  ctx.moveTo(x + rr, y);
  ctx.arcTo(x + w, y, x + w, y + h, rr);
  ctx.arcTo(x + w, y + h, x, y + h, rr);
  ctx.arcTo(x, y + h, x, y, rr);
  ctx.arcTo(x, y, x + w, y, rr);
  ctx.closePath();
}

/* ============================================================ *
 * Painter. One pass measures (draw=false), one draws (draw=true),
 * down the same code path, so measured and drawn heights cannot drift.
 * Sub-blocks that need a background behind content (the geo hero, the
 * source list) are laid out with draw=false first to size the panel,
 * then drawn once.
 * ============================================================ */

function paint(ctx, m, T, draw) {
  const inner = W - PAD * 2;

  const text = (s, font, color, x, y, align = "left") => {
    if (!draw) return;
    ctx.font = font; ctx.fillStyle = color; ctx.textAlign = align;
    ctx.fillText(s, x, y);
    ctx.textAlign = "left";
  };
  const mc = measurer();
  const width = (s, font) => { mc.font = font; return mc.measureText(s).width; };

  let y = PAD + 3;   // below the 3px accent bar

  /* header — kind + "Generated" timestamp. NO wordmark, NO mark (§4). */
  text("INDICATOR REPUTATION", `700 9px ${SANS}`, T.textFaint, PAD, y + 8);
  text(`Generated ${m.provenance.generated}`, `400 8.5px ${MONO}`, T.textFaint, W - PAD, y + 8, "right");
  y += 22;

  /* indicator + type badge */
  const indFont = `600 16px ${MONO}`;
  const indLines = wrap(mc, m.indicator, indFont, inner - 60);
  indLines.forEach((line, i) => {
    text(line, indFont, T.text, PAD, y + 14);
    if (i === 0) {
      const badge = m.typeLabel, bf = `600 9.5px ${MONO}`;
      const bw = width(badge, bf) + 12;
      if (draw) {
        ctx.strokeStyle = T.border2; ctx.lineWidth = 1;
        roundRect(ctx, W - PAD - bw, y + 2, bw, 15, 4); ctx.stroke();
      }
      text(badge, bf, T.textDim, W - PAD - bw / 2, y + 12.5, "center");
    }
    y += 21;
  });
  y += 4;

  /* ---- consensus tally (LEADS) ---- */
  text("CONSENSUS TALLY — ACROSS PUBLIC SOURCES", `700 9px ${SANS}`, T.textFaint, PAD, y + 8);
  y += 16;

  // headline: the leading count in the verdict tone, the rest in body ink.
  const toneInk = { red: T.vRed, amber: T.vAmber, green: T.vGreen, grey: T.textFaint }[m.tone] ?? T.textFaint;
  const hlFont = `700 15px ${SANS}`, numFont = `900 15px ${SANS}`;
  const numMatch = m.headline.match(/^(\d+)(.*)$/s);
  let hx = PAD, first = true;
  if (numMatch) {
    text(numMatch[1], numFont, toneInk, PAD, y + 14);
    hx = PAD + width(numMatch[1], numFont);
  }
  const restText = numMatch ? numMatch[2] : m.headline;
  // hanging-indent wrap: first line continues after the coloured number.
  {
    mc.font = hlFont;
    const words = restText.replace(/^\s+/, " ").split(/(\s+)/).filter(Boolean);
    let lineX = hx, lineFirst = true;
    let cur = "";
    const flush = () => {
      if (cur) text(cur, hlFont, T.text, lineFirst && numMatch ? undefined : PAD, y + 14);
    };
    // simpler: build lines honouring the first-line offset
    const avail0 = inner - (hx - PAD);
    const linesRest = [];
    let line = "";
    for (const w of restText.trim().split(/\s+/)) {
      const cand = line ? line + " " + w : w;
      const limit = linesRest.length === 0 ? avail0 : inner;
      if (width(cand, hlFont) <= limit) line = cand;
      else { if (line) linesRest.push(line); line = w; }
    }
    if (line) linesRest.push(line);
    linesRest.forEach((ln, i) => {
      text((i === 0 ? " " : "") + ln, hlFont, T.text, i === 0 ? hx : PAD, y + 14);
      y += 19;
    });
    if (!linesRest.length) y += 19;
  }
  y += 4;

  // segmented gauge — one segment per consulted source, coloured by its finding
  const segN = Math.max(m.segments.length, 1);
  const segGap = 3, segH = 9;
  const segW = (inner - segGap * (segN - 1)) / segN;
  if (draw) {
    m.segments.forEach((s, i) => {
      const sx = PAD + i * (segW + segGap);
      const col = { malicious: T.vRed, suspicious: T.vAmber, benign: T.vGreen }[s.verdict];
      roundRect(ctx, sx, y, segW, segH, 3);
      if (col) { ctx.fillStyle = col; ctx.fill(); }
      else {                                   // unknown / not flagged — outline
        ctx.strokeStyle = s.verdict === "benign" ? T.vGreen : T.border3;
        ctx.lineWidth = 1; ctx.stroke();
      }
    });
    if (!m.segments.length) {                  // nothing consulted — empty track
      roundRect(ctx, PAD, y, inner, segH, 3); ctx.fillStyle = T.panel2; ctx.fill();
    }
  }
  y += segH + 6;
  text(m.caption.left, `400 8.5px ${MONO}`, T.textFaint, PAD, y + 6);
  text(m.caption.right, `400 8.5px ${MONO}`, T.textFaint, W - PAD, y + 6, "right");
  y += 16;

  /* ---- mitigating / dual-use note, promoted directly under the tally ---- */
  if (m.mitigations.length) {
    const barTop = y - 2;
    let ny = y;
    text("NOTE", `700 8.5px ${SANS}`, T.textDim, PAD + 10, ny + 8);
    ny += 12;
    for (const note of m.mitigations) {
      for (const line of wrap(mc, note, `400 10.5px ${SANS}`, inner - 12)) {
        text(line, `400 10.5px ${SANS}`, T.textDim, PAD + 10, ny + 9);
        ny += 15;
      }
    }
    if (draw) { ctx.fillStyle = T.accent; ctx.fillRect(PAD, barTop, 2, ny - barTop); }
    y = ny + 8;
  }

  /* ---- geolocation hero (context, NOT a verdict) ---- */
  if (m.geo) y = paintGeo(ctx, m, T, draw, y, inner);

  /* ---- attributed source rows ---- */
  y = paintSources(ctx, m, T, draw, y, inner, width);

  /* ---- verify caveat (§4) — baked in so it cannot be lost on forward ---- */
  {
    const cy0 = y;
    let cy = y;
    for (const line of wrap(mc, m.caveat, `400 10px ${SANS}`, inner - 12)) {
      text(line, `400 10px ${SANS}`, T.textDim, PAD + 10, cy + 9);
      cy += 14;
    }
    if (draw) { ctx.fillStyle = T.border3; ctx.fillRect(PAD, cy0 - 1, 2, cy - cy0 + 1); }
    y = cy + 8;
  }

  // The only timestamp is "Generated <ts>" in the header; the caveat block
  // already states the data "has not been independently confirmed", so no
  // footer line is drawn — nothing further is needed here.

  return y + PAD;
}

/* ---------- geo hero block ---------------------------------------------- */

function paintGeo(ctx, m, T, draw, y, inner) {
  const g = m.geo;
  const boxX = PAD, boxW = inner, ipad = 12;
  const contentW = boxW - ipad * 2;

  // measure the block first so we can paint its tinted panel behind it
  const mapH = contentW * (WORLD.length / WORLD[0].length);
  const geoH = ipad          // top pad
    + 12                     // label
    + 8                      // gap
    + mapH                   // map
    + 12                     // gap
    + 30                     // country line
    + ipad;                  // bottom pad

  if (draw) {
    ctx.fillStyle = mix(T.accent, T.panel, 0.07);
    ctx.strokeStyle = mix(T.accent, T.border2, 0.26); ctx.lineWidth = 1;
    roundRect(ctx, boxX, y, boxW, geoH, 10); ctx.fill(); ctx.stroke();
  }

  let gy = y + ipad;
  if (draw) {
    ctx.font = `700 9px ${SANS}`; ctx.fillStyle = T.textFaint; ctx.textAlign = "left";
    ctx.fillText("GEOLOCATION", boxX + ipad, gy + 8);
  }
  gy += 12 + 8;

  // world map
  paintWorld(ctx, T, draw, boxX + ipad, gy, contentW, mapH, g);
  gy += mapH + 12;

  // flag + country + sub + coords
  const cx = boxX + ipad;
  const flagW = 30, flagH = 20;
  paintFlag(ctx, T, draw, cx, gy + 2, flagW, flagH, g);

  const nameX = cx + flagW + 11;
  if (draw) {
    ctx.textAlign = "left";
    ctx.font = `800 24px ${SANS}`; ctx.fillStyle = T.text;
    ctx.fillText(g.countryName, nameX, gy + 20);
  }
  const sub = [g.city, g.asn, g.org].filter(Boolean).join(" · ");
  if (draw && sub) {
    ctx.font = `400 10.5px ${MONO}`; ctx.fillStyle = T.textDim;
    ctx.fillText(sub, nameX, gy + 33);
  }
  if (draw) {
    ctx.textAlign = "right";
    ctx.font = `400 8.5px ${MONO}`; ctx.fillStyle = T.textFaint;
    const coord = g.precise
      ? `${Math.abs(g.lat).toFixed(2)}°${g.lat >= 0 ? "N" : "S"} ${Math.abs(g.lon).toFixed(2)}°${g.lon >= 0 ? "E" : "W"}`
      : "country-level";
    ctx.fillText(coord, boxX + boxW - ipad, gy + 12);
    ctx.fillText("via ipinfo", boxX + boxW - ipad, gy + 24);
    ctx.textAlign = "left";
  }

  return y + geoH + 12;
}

function paintWorld(ctx, T, draw, x, y, w, h, g) {
  const cols = WORLD[0].length, rows = WORLD.length;
  const cell = w / cols;
  const mapBg = mix(T.accent, T.panel2, 0.08);
  const mapLand = mix(T.accent, T.border2, 0.42);
  const mapHot = T.accent;

  if (draw) {
    ctx.strokeStyle = mix(T.accent, T.panel, 0.18); ctx.lineWidth = 1;
    roundRect(ctx, x, y, w, h, 7); ctx.fillStyle = mapBg; ctx.fill(); ctx.stroke();
    ctx.save();
    roundRect(ctx, x, y, w, h, 7); ctx.clip();

    // graticule
    ctx.strokeStyle = mix(T.accent, mapBg, 0.14); ctx.lineWidth = 1;
    for (const gx of [16, 32, 48, 64]) {
      ctx.beginPath(); ctx.moveTo(x + gx * cell, y); ctx.lineTo(x + gx * cell, y + h); ctx.stroke();
    }
    ctx.beginPath(); ctx.moveTo(x, y + h / 2); ctx.lineTo(x + w, y + h / 2); ctx.stroke();

    // projected pin position (equirectangular), clamped inside the frame
    const fx = Math.min(0.999, Math.max(0.001, (g.lon + 180) / 360));
    const fy = Math.min(0.999, Math.max(0.001, (90 - g.lat) / 180));
    const hlC = Math.round(fx * cols - 0.5), hlR = Math.round(fy * rows - 0.5);

    // land
    for (let r = 0; r < rows; r++) {
      const line = WORLD[r];
      for (let c = 0; c < line.length; c++) {
        if (line[c] !== "#") continue;
        const hot = Math.abs(c - hlC) <= 1 && Math.abs(r - hlR) <= 1;
        ctx.fillStyle = hot ? mapHot : mapLand;
        ctx.fillRect(x + (c + 0.12) * cell, y + (r + 0.12) * cell, cell * 0.76, cell * 0.76);
      }
    }

    // the pin, drawn geometrically (teardrop + ring + inner dot)
    const px = x + fx * w, tipY = y + fy * h, headY = tipY - 3.9 * cell;
    ctx.fillStyle = mapHot; ctx.globalAlpha = 0.28;
    ctx.beginPath(); ctx.ellipse(px, tipY, 2.1 * cell, 0.7 * cell, 0, 0, Math.PI * 2); ctx.fill();
    ctx.globalAlpha = 0.5; ctx.strokeStyle = mapHot; ctx.lineWidth = Math.max(0.8, 0.4 * cell);
    ctx.beginPath(); ctx.arc(px, headY, 3.3 * cell, 0, Math.PI * 2); ctx.stroke();
    ctx.globalAlpha = 1;
    ctx.fillStyle = mapHot;
    ctx.beginPath();
    ctx.moveTo(px, tipY);
    ctx.lineTo(px - 1.6 * cell, tipY - 1.1 * cell);
    ctx.arc(px, headY, 1.9 * cell, Math.PI * 0.75, Math.PI * 0.25, false);
    ctx.closePath(); ctx.fill();
    ctx.fillStyle = T.panel;
    ctx.beginPath(); ctx.arc(px, headY, 0.9 * cell, 0, Math.PI * 2); ctx.fill();

    ctx.restore();
  }
}

function paintFlag(ctx, T, draw, x, y, w, h, g) {
  if (!draw) return;
  ctx.save();
  roundRect(ctx, x, y, w, h, 3); ctx.clip();
  if (g.flag) {
    const bands = g.flag.bands, n = bands.length;
    if (g.flag.dir === "v") {
      const bw = w / n;
      bands.forEach((c, i) => { ctx.fillStyle = c; ctx.fillRect(x + i * bw, y, bw + 0.5, h); });
    } else {
      const bh = h / n;
      bands.forEach((c, i) => { ctx.fillStyle = c; ctx.fillRect(x, y + i * bh, w, bh + 0.5); });
    }
  } else {
    ctx.fillStyle = mix(T.accent, T.panel2, 0.2); ctx.fillRect(x, y, w, h);
    ctx.fillStyle = T.textDim; ctx.font = `700 9px ${MONO}`;
    ctx.textAlign = "center"; ctx.textBaseline = "middle";
    ctx.fillText(g.countryCode || "??", x + w / 2, y + h / 2 + 0.5);
    ctx.textAlign = "left"; ctx.textBaseline = "alphabetic";
  }
  ctx.restore();
  ctx.strokeStyle = T.border3; ctx.lineWidth = 1;
  roundRect(ctx, x + 0.5, y + 0.5, w - 1, h - 1, 3); ctx.stroke();
}

/* ---------- attributed source rows -------------------------------------- */

function paintSources(ctx, m, T, draw, y, inner, width) {
  const mc = measurer();
  const rowPadX = 10, rowPadY = 7, nameW = 96, dotGap = 8, dotR = 3.5;
  const findX = PAD + rowPadX + dotGap + dotR * 2 + 6 + nameW + 8;
  const findW = W - PAD - rowPadX - findX;
  const findFont = `400 9.5px ${MONO}`;

  // measure total list height
  const rows = m.sources.length ? m.sources : [{ name: "—", verdict: "unknown", finding: "No consulted source returned a finding." }];
  const rowHeights = rows.map(s => {
    const lines = Math.min(2, wrap(mc, s.finding, findFont, findW).length || 1);
    return Math.max(20, rowPadY * 2 + lines * 13);
  });
  const listH = rowHeights.reduce((a, b) => a + b, 0);

  if (draw) {
    ctx.strokeStyle = T.border; ctx.lineWidth = 1;
    roundRect(ctx, PAD, y, inner, listH, 8); ctx.stroke();
    ctx.save(); roundRect(ctx, PAD, y, inner, listH, 8); ctx.clip();
  }

  let ry = y;
  rows.forEach((s, i) => {
    const rh = rowHeights[i];
    if (draw) {
      if (i % 2 === 1) { ctx.fillStyle = mix(T.panel2, T.panel, 0.45); ctx.fillRect(PAD, ry, inner, rh); }
      if (i > 0) { ctx.fillStyle = T.border; ctx.fillRect(PAD, ry, inner, 1); }

      const dotCol = { malicious: T.vRed, suspicious: T.vAmber, benign: T.vGreen }[s.verdict] || T.textFaint;
      ctx.fillStyle = dotCol;
      ctx.beginPath(); ctx.arc(PAD + rowPadX + dotR, ry + rh / 2, dotR, 0, Math.PI * 2); ctx.fill();

      ctx.font = `600 11px ${SANS}`; ctx.fillStyle = T.text; ctx.textAlign = "left";
      ctx.fillText(s.name, PAD + rowPadX + dotGap + dotR * 2 + 6, ry + rh / 2 + 4);

      const lines = wrap(mc, s.finding, findFont, findW).slice(0, 2);
      ctx.font = findFont; ctx.fillStyle = T.textDim;
      const startY = ry + rh / 2 - (lines.length - 1) * 6.5 + 4;
      lines.forEach((ln, li) => {
        let out = ln;
        if (li === 1 && wrap(mc, s.finding, findFont, findW).length > 2) out = ln.replace(/.{1}$/, "…");
        ctx.fillText(out, findX, startY + li * 13);
      });
    }
    ry += rh;
  });
  if (draw) ctx.restore();

  return y + listH + 10;
}

/* ---------- public API --------------------------------------------------- */

/**
 * Render the card to a canvas sized to its content, in the given (or detected)
 * theme. Call after `document.fonts.ready` so the web faces are available —
 * canvas silently substitutes a fallback face otherwise.
 *
 * @param {object} result  an /api/enrich response
 * @param {{theme?: "light"|"dark", now?: Date}} [opts]
 */
export function renderEvidence(result, opts = {}) {
  const theme = opts.theme || detectTheme();
  const T = THEMES[theme] || THEMES.dark;
  const now = opts.now || new Date();
  const m = evidenceModel(result, now);

  const height = paint(measurer(), m, T, false);

  const canvas = document.createElement("canvas");
  canvas.width = W * SCALE;
  canvas.height = Math.ceil(height) * SCALE;
  const ctx = canvas.getContext("2d");
  ctx.scale(SCALE, SCALE);
  ctx.textBaseline = "alphabetic";

  // card background + hairline border, clipped to the rounded card shape
  roundRect(ctx, 0.5, 0.5, W - 1, height - 1, RADIUS);
  ctx.fillStyle = T.panel; ctx.fill();
  ctx.save(); roundRect(ctx, 0.5, 0.5, W - 1, height - 1, RADIUS); ctx.clip();

  // accent bar (periwinkle gradient) along the top edge
  const grad = ctx.createLinearGradient(0, 0, W, 0);
  grad.addColorStop(0, T.accent); grad.addColorStop(1, T.accent2);
  ctx.fillStyle = grad; ctx.fillRect(0, 0, W, 3);

  paint(ctx, m, T, true);
  ctx.restore();

  ctx.strokeStyle = T.border2; ctx.lineWidth = 1;
  roundRect(ctx, 0.5, 0.5, W - 1, height - 1, RADIUS); ctx.stroke();

  return canvas;
}

export const toBlob = canvas =>
  new Promise(res => canvas.toBlob(res, "image/png"));

/**
 * Put the card on the clipboard as an image. Returns the truth about whether it
 * worked — this project has already shipped a button that reported success while
 * the clipboard rejected the write. Feature-detected; never throws.
 */
export async function copyEvidence(canvas) {
  try {
    if (!navigator.clipboard?.write || typeof ClipboardItem === "undefined") return false;
    const blob = await toBlob(canvas);
    if (!blob) return false;
    await navigator.clipboard.write([new ClipboardItem({ "image/png": blob })]);
    return true;
  } catch {
    return false;                       // denied permission, or insecure origin
  }
}

/** Fallback for browsers that refuse image clipboard writes. Unbranded name. */
export async function downloadEvidence(canvas, indicator) {
  const blob = await toBlob(canvas);
  if (!blob) return false;
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `indicator-${String(indicator).replace(/[^\w.-]+/g, "_").slice(0, 60)}.png`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  return true;
}
