// data.js — payload loading, freshness, escaping.
// Defence in depth: the pipeline sanitizes, the site STILL escapes at render.
// Two real bypasses closed upstream (unterminated tags borrowing a `>`, and
// scheme-prefix URL checks allowing attribute breakout) — do not assume the
// data is clean here either.
const FILES = ["feed", "cves", "actors", "malware", "health", "sources", "trends"];

export const esc = s => String(s ?? "").replace(/[&<>"'`]/g,
  c => "&#" + c.charCodeAt(0) + ";");

export function safeUrl(u) {
  try {
    const p = new URL(String(u ?? ""));
    return (p.protocol === "http:" || p.protocol === "https:") ? esc(p.href) : "";
  } catch { return ""; }
}

export async function loadAll() {
  const data = {};
  await Promise.all([...FILES, "brief"].map(async name => {
    try {
      const r = await fetch(`data/${name}.json`, { cache: "no-cache" });
      data[name] = r.ok ? await r.json() : null;   // brief.json 404s until Phase C
    } catch { data[name] = null; }
  }));
  return data;
}

export const ageMin = iso =>
  iso ? Math.max(0, (Date.now() - Date.parse(iso)) / 60000) : Infinity;

export function rel(iso) {
  const m = ageMin(iso);
  if (!isFinite(m)) return "—";
  if (m < 1) return "Now";
  if (m < 60) return `${Math.round(m)}m ago`;
  if (m < 1440) return `${Math.round(m / 60)}h ago`;
  return `${Math.round(m / 1440)}d ago`;
}

/**
 * Copy to the clipboard, honestly.
 *
 * navigator.clipboard.writeText() REJECTS — denied permission, an unfocused
 * document, a browser that gates it behind a user gesture we have already lost.
 * Firing it bare did two bad things: it raised an unhandled rejection into the
 * console, and the button still flashed "COPIED ✓" for a copy that never
 * happened, so an analyst pasted stale content into a ticket.
 */
export async function copyText(text) {
  try { await navigator.clipboard?.writeText(text); return true; }
  catch { return false; }
}

/** Copy, then say what actually happened on the button that triggered it. */
export async function copyToButton(btn, text, was = btn.textContent) {
  btn.textContent = (await copyText(text)) ? "COPIED ✓" : "COPY BLOCKED";
  setTimeout(() => { btn.textContent = was; }, 1200);
}

export const day = iso => (iso || "").slice(0, 10) || "—";
export const num = n => (n ?? 0).toLocaleString("en-US");

/** Elapsed clock, e.g. "+00:14:32" — liveness measured on OUR clock, never faked. */
export function elapsed(iso) {
  const ms = iso ? Date.now() - Date.parse(iso) : NaN;
  if (!isFinite(ms) || ms < 0) return "—";
  const s = Math.floor(ms / 1000);
  const pad = n => String(n).padStart(2, "0");
  return `+${pad(Math.floor(s / 3600))}:${pad(Math.floor(s / 60) % 60)}:${pad(s % 60)}`;
}

/** Countdown to the next scheduled pull (collectors run at :11 and :41). */
export function nextPull() {
  const now = new Date();
  const m = now.getMinutes(), s = now.getSeconds();
  const mins = m < 11 ? 11 - m : m < 41 ? 41 - m : 71 - m;
  const total = mins * 60 - s;
  const pad = n => String(n).padStart(2, "0");
  return `−${pad(Math.floor(total / 60))}:${pad(total % 60)}`;
}

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[a-z]{2,}$/i;

export function detectType(q) {
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(q)) return "ipv4";
  if (/^[a-f0-9]{64}$/i.test(q)) return "sha256";
  if (/^[a-f0-9]{40}$/i.test(q)) return "sha1";
  if (/^[a-f0-9]{32}$/i.test(q)) return "md5";
  if (/^cve-\d{4}-\d{4,7}$/i.test(q)) return "cve";
  if (EMAIL_RE.test(q)) return "email";
  if (/^https?:\/\//i.test(q)) return "url";
  if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(q)) return "domain";
  return "";
}

/** Refang analyst-pasted indicators: evil[.]com, hxxp://, 1.2.3[.]4 */
export const refang = s => String(s ?? "").trim()
  .replace(/\[\.\]|\(\.\)|\{\.\}/g, ".")
  .replace(/\[:\]/g, ":")
  .replace(/\bhxxp/gi, "http")
  .replace(/\[at\]/gi, "@");

export const STALE_FEED_MIN = 90, STALE_BRIEF_MIN = 26 * 60;

export function staleness(data) {
  const out = [];
  if (ageMin(data.feed?.generated_at) > STALE_FEED_MIN)
    out.push(`FEED STALE · ${rel(data.feed?.generated_at)}`);
  if (data.brief && ageMin(data.brief.generated_at) > STALE_BRIEF_MIN)
    out.push(`BRIEF STALE · ${rel(data.brief.generated_at)}`);
  return out;
}
