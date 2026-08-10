// popup.js — the toolbar popup. Paste an indicator (or arrive pre-loaded from
// the context menu), classify it, call the LIVE /api/enrich on the configured
// origin, and render a compact multi-source verdict.
//
// SECURITY RULE (same law the site renders by): every value in the enrich
// response is attacker-influenced — an ISP name, a VirusTotal engine string, a
// source URL. It is NEVER interpolated into HTML. This file builds DOM with
// createElement + textContent only, and every link href is passed through
// safeUrl() so a `javascript:`/`data:` URL can never become a live link.

import {
  refang, detectType, isEnrichable, safeUrl,
  normalizeOrigin, enrichUrl, reportUrl, DEFAULT_ORIGIN,
} from "./lib/indicators.js";

const $ = id => document.getElementById(id);
const form = $("form"), input = $("q"), chip = $("chip"),
      out = $("out"), fullBtn = $("full"), optsBtn = $("opts");

let origin = DEFAULT_ORIGIN;   // resolved from storage on load
let currentQ = "";             // the last indicator we acted on

/* ---- verdict vocabulary (mirrors site/js/enrich-client.js) --------------- */
const TONE = { malicious: "red", suspicious: "orange", benign: "green", unknown: "muted" };
const WORD = {
  malicious: "MALICIOUS", suspicious: "SUSPICIOUS",
  benign: "NO ADVERSE FINDINGS", unknown: "NO DATA ON RECORD",
};
const toneOf = v => TONE[v] ?? "muted";
const wordOf = v => WORD[v] ?? "NO DATA ON RECORD";

/* ---- tiny DOM builder (no innerHTML with dynamic data) ------------------- */
function el(tag, opts = {}, kids = []) {
  const n = document.createElement(tag);
  if (opts.class) n.className = opts.class;
  if (opts.text != null) n.textContent = opts.text;   // textContent = safe
  if (opts.title) n.title = opts.title;
  for (const [k, v] of Object.entries(opts.attrs || {})) n.setAttribute(k, v);
  for (const k of [].concat(kids)) {
    if (k == null || k === false) continue;
    n.appendChild(typeof k === "string" ? document.createTextNode(k) : k);
  }
  return n;
}
const clear = node => { while (node.firstChild) node.removeChild(node.firstChild); };

/* ---- states -------------------------------------------------------------- */
function showMsg(text, isErr = false) {
  clear(out);
  out.appendChild(el("div", { class: "msg" + (isErr ? " err" : ""), text }));
}
function showLoading(q) {
  clear(out);
  out.appendChild(el("div", { class: "loading" }, [
    el("span", { class: "ping", attrs: { "aria-hidden": "true" } }),
    el("span", { text: `Checking public reputation sources for ${q}…` }),
  ]));
}

/* ---- render a single source row ----------------------------------------- */
function sourceRow(s) {
  const isContext = s.kind === "context";
  const v = String(s.verdict ?? "unknown").toLowerCase();
  const badgeText = isContext ? "CONTEXT" : (WORD[v] ? v.toUpperCase() : "UNKNOWN");
  const badgeTone = isContext ? "muted" : toneOf(v);

  const head = el("div", { class: "src-h" }, [
    el("span", { class: "src-name", text: String(s.name ?? "source") }),
    el("span", { class: `badge tone-${badgeTone}`, text: badgeText }),
  ]);

  const row = el("div", { class: "src" }, [head]);
  if (s.headline) row.appendChild(el("div", { class: "src-head", text: String(s.headline) }));

  const href = safeUrl(s.url);
  if (href) {
    row.appendChild(el("a", {
      class: "verify",
      text: `verify at ${String(s.name ?? "source")} ↗`,
      attrs: { href, target: "_blank", rel: "noopener noreferrer" },
    }));
  }
  return row;
}

/* ---- render the composite verdict --------------------------------------- */
function renderResult(result, q) {
  clear(out);
  const overall = String(result.verdict ?? "unknown").toLowerCase();
  const sources = Array.isArray(result.sources) ? result.sources : [];
  const checked = String(result.checked_at ?? "").replace("T", " ").slice(0, 16);
  const n = sources.length;

  // header
  const head = el("div", { class: "vhead" }, [
    el("span", { class: `vword tone-${toneOf(overall)}`, text: wordOf(overall) }),
  ]);
  if (result.score != null && result.score !== "")
    head.appendChild(el("span", { class: "vscore", text: `score ${result.score}` }));
  if (result.partial)
    head.appendChild(el("span", { class: "partial", text: "partial" }));
  head.appendChild(el("span", {
    class: "vmeta",
    text: `${n} source${n === 1 ? "" : "s"}${checked ? " · " + checked + " UTC" : ""}`,
  }));
  out.appendChild(head);

  // one row per source
  sources.forEach(s => out.appendChild(sourceRow(s)));

  // errors — named, never hidden
  const errs = Array.isArray(result.errors) ? result.errors : [];
  if (errs.length) {
    out.appendChild(el("div", { class: "gaps" }, [
      el("div", { class: "l", text: "Not consulted — named, never hidden" }),
      el("div", {
        class: "v",
        text: errs.map(e => `${e.source} (${e.reason})`).join(" · "),
      }),
    ]));
  }

  if (!n && !errs.length)
    out.appendChild(el("div", { class: "msg", text: "No sources returned a verdict." }));
}

/* ---- the lookup ---------------------------------------------------------- */
async function fetchEnrich(type, q) {
  const url = enrichUrl(origin, type, q);
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 12000);
  try {
    const r = await fetch(url, { signal: ctrl.signal, headers: { accept: "application/json" } });
    let body = null;
    try { body = await r.json(); } catch { /* non-JSON error body */ }
    if (r.ok && body && Array.isArray(body.sources)) return { status: "ok", result: body };
    if (body && body.error) return { status: "declined", reason: String(body.error) };
    return { status: "unavailable", reason: `HTTP ${r.status}` };
  } catch (e) {
    return {
      status: "unavailable",
      reason: e && e.name === "AbortError" ? "timed out" : (e && e.message) || "network error",
    };
  } finally {
    clearTimeout(timer);
  }
}

async function run(raw) {
  const q = refang(raw);
  currentQ = q;
  input.value = q;
  if (!q) { chip.hidden = true; showMsg("Paste an indicator, or select text on a page and use “Check in SOCDesk”."); return; }

  const type = detectType(q);
  if (type) { chip.hidden = false; chip.textContent = type; } else { chip.hidden = true; }

  if (!type) { showMsg(`“${q}” isn’t a recognizable indicator. Use “Open full report” to search it in SOCDesk.`, true); return; }

  if (!isEnrichable(type)) {
    // cve / email — not enriched by design; the full report handles these.
    showMsg(`${type.toUpperCase()} isn’t a live-enriched type. Use “Open full report” to look it up in SOCDesk.`);
    return;
  }

  showLoading(q);
  const outcome = await fetchEnrich(type, q);
  if (outcome.status === "ok") return renderResult(outcome.result, q);
  if (outcome.status === "declined")
    return showMsg(`Live enrichment declined: ${outcome.reason}. Use “Open full report” to see the static verdict.`, true);
  return showMsg(`Live reputation unavailable: ${outcome.reason}. Check the origin in Options, or use “Open full report”.`, true);
}

/* ---- wiring -------------------------------------------------------------- */
form.addEventListener("submit", e => { e.preventDefault(); run(input.value); });

fullBtn.addEventListener("click", () => {
  const q = currentQ || refang(input.value);
  const url = q ? reportUrl(origin, q) : normalizeOrigin(origin) + "/";
  chrome.tabs.create({ url });
});

optsBtn.addEventListener("click", () => chrome.runtime.openOptionsPage());

/* ---- boot: resolve origin, then run any pending context-menu lookup ------ */
(async function boot() {
  try {
    const { origin: stored } = await chrome.storage.sync.get("origin");
    origin = normalizeOrigin(stored);
  } catch { origin = DEFAULT_ORIGIN; }

  let pending = null;
  try {
    const s = await chrome.storage.session.get("pending");
    pending = s && s.pending;
    if (pending) await chrome.storage.session.remove("pending");   // one-shot
  } catch { /* session storage unavailable */ }

  input.focus();
  if (pending && pending.q) run(pending.q);
  else showMsg("Paste an indicator, or select text on a page and use “Check in SOCDesk”.");
})();
