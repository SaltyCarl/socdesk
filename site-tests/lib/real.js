// real.js — every expected value in this suite is computed from the data that
// is actually published in site/data/. Nothing is hardcoded: the pipeline
// refreshes twice an hour and a frozen count would rot within the day.
const fs = require("fs");
const path = require("path");

const SITE = path.resolve(__dirname, "..", "..", "site");

function json(name) {
  const p = path.join(SITE, "data", `${name}.json`);
  if (!fs.existsSync(p)) return null;
  return JSON.parse(fs.readFileSync(p, "utf8"));
}

const feed    = () => json("feed");
const cves    = () => json("cves");
const health  = () => json("health");
const sources = () => json("sources");
const actors  = () => json("actors");
const malware = () => json("malware");

/** The masthead's "TRACKED OBJECTS" contract, recomputed from the payloads. */
function trackedTotal() {
  return (feed()?.items?.length ?? 0) + (cves()?.cves?.length ?? 0)
       + (actors()?.profiles?.length ?? 0) + (malware()?.profiles?.length ?? 0);
}

/** The row the verdict engine must call ACTIVELY EXPLOITED with a real gauge. */
function topKevCve() {
  return (cves()?.cves ?? []).filter(c => c.kev)
    .sort((a, b) => (b.epss ?? 0) - (a.epss ?? 0))[0];
}

/** Most-covered vendor in the corpus — a watchlist term guaranteed to match. */
function busiestVendor() {
  const counts = new Map();
  for (const c of cves()?.cves ?? [])
    for (const v of c.vendors ?? []) {
      const k = String(v).toLowerCase();
      counts.set(k, (counts.get(k) ?? 0) + 1);
    }
  return [...counts].sort((a, b) => b[1] - a[1])[0];   // [vendor, hits]
}

/** The exact haystack views.js `visible()` searches — kept in lockstep with it. */
const hay = i => (i.title + " " + i.summary + " " +
  Object.values(i.entities || {}).flat().join(" ")).toLowerCase();

/** A search token that provably narrows: present in some items, absent in others. */
function narrowingTerm() {
  const items = feed()?.items ?? [];
  const freq = new Map();
  for (const i of items)
    for (const w of new Set((i.title.toLowerCase().match(/[a-z]{5,}/g) ?? [])))
      freq.set(w, (freq.get(w) ?? 0) + 1);
  const best = [...freq]
    .filter(([, n]) => n > 1 && n < items.length)
    .sort((a, b) => b[1] - a[1])[0];
  if (!best) throw new Error("no usable search term in the published feed");
  const term = best[0];
  return { term, expected: items.filter(i => hay(i).includes(term)).length };
}

function categoryCounts() {
  const items = feed()?.items ?? [];
  const out = new Map([["all", items.length]]);
  for (const i of items) out.set(i.category, (out.get(i.category) ?? 0) + 1);
  return out;
}

/** Raw Content-Security-Policy value as published in site/_headers. */
function cspFromHeaders() {
  const text = fs.readFileSync(path.join(SITE, "_headers"), "utf8");
  const line = text.split(/\r?\n/).find(l => /^\s*Content-Security-Policy:/i.test(l));
  if (!line) throw new Error("no Content-Security-Policy line in site/_headers");
  return line.replace(/^\s*Content-Security-Policy:\s*/i, "").trim();
}

/** Console errors we accept: brief.json is unpublished until Phase C by design. */
const BENIGN = [
  /data\/brief\.json/i,
  /the server responded with a status of 404/i,
];

/**
 * Attach a console/pageerror recorder. Returns () => string[] of real errors.
 * Optionally treat blocked-CDN failures as expected (degraded-mode specs).
 */
function watchConsole(page, extraBenign = []) {
  const errs = [];
  page.on("console", m => { if (m.type() === "error") errs.push(m.text()); });
  page.on("pageerror", e => errs.push(`pageerror: ${e.message}`));
  const ok = [...BENIGN, ...extraBenign];
  return () => errs.filter(t => !ok.some(re => re.test(t)));
}

module.exports = {
  SITE, json, feed, cves, health, sources, actors, malware,
  trackedTotal, topKevCve, busiestVendor, categoryCounts, narrowingTerm, hay,
  cspFromHeaders, watchConsole,
};
