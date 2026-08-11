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

/* ---- consensus-tally language --------------------------------------------
 * SOCDesk emits NO verdict word of its own; it presents a source-consensus
 * tally ("N of M sources flagged this") and each source's attributed finding.
 * This wording is a BYTE-IDENTICAL copy of the site's (site/js/verdict.js),
 * both keyed off docs/VERDICT-LANGUAGE.md and the SAME /api/enrich contract —
 * never off each other. Change the spec, then change both surfaces.
 * ------------------------------------------------------------------------- */
const toneClass = tone =>
  ({ red: "red", amber: "orange", green: "green", grey: "muted" }[tone] ?? "muted");

function tallyHeadline(flagged, consulted) {
  if (consulted === 0)
    return "No reputation data available from consulted sources. Not evidence of safety.";
  if (flagged === 0)
    return `0 of ${consulted} consulted sources flagged this — no adverse findings. Not a clearance.`;
  return `${flagged} of ${consulted} consulted sources flagged this as adverse.`;
}
function assessmentLine(flagged, consulted) {
  if (consulted === 0)
    return "No reputation data available from consulted sources — not evidence of safety.";
  return `${flagged} of ${consulted} public reputation sources flagged this as adverse.`;
}
const defangText = s =>
  String(s).replace(/\./g, "[.]").replace(/^http/i, "hxxp");
const stampUTC = d => new Date(d).toISOString().replace("T", " ").slice(0, 16) + " UTC";

/** The §4 escalation block as text — identical wording to the site's
 *  tallyEscalation(). What the analyst copies IS what the site would copy. */
function tallyEscalation(result, now = new Date()) {
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
  return lines.join("\n");
}

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

/* ---- render a single source row (attributed finding, no verdict chip) ---- */
function sourceRow(s) {
  const isContext = s.kind === "context";
  const head = el("div", { class: "src-h" }, [
    el("span", { class: "src-name", text: String(s.name ?? "source") }),
    isContext ? el("span", { class: "badge tone-muted", text: "context — not a verdict" }) : null,
  ]);

  const row = el("div", { class: "src" }, [head]);
  // The source's OWN finding, stated as fact — never promoted to a SOCDesk
  // verdict (§3). The tally header above is the only assessment SOCDesk makes.
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

/* ---- the ratio-led escalation card (§4) — copy straight into an email ---- */
function escalationCard(result) {
  const text = tallyEscalation(result);
  const btn = el("button", { class: "esc-copy", text: "COPY",
    attrs: { type: "button" } });
  const head = el("div", { class: "esc-h" }, [
    el("span", { class: "esc-cap", text: "Escalation — copy into the ticket" }),
    btn,
  ]);
  // Render the exact copied text, line for line (textContent — never innerHTML),
  // so what the analyst reads equals what lands in the email.
  const body = el("div", { class: "esc-body" });
  for (const line of text.split("\n"))
    body.appendChild(el("div", { class: "esc-line", text: line || " " }));

  btn.addEventListener("click", async () => {
    let ok = false;
    try { await navigator.clipboard.writeText(text); ok = true; } catch { ok = false; }
    btn.textContent = ok ? "Copied ✓" : "Copy blocked";
    setTimeout(() => { btn.textContent = "COPY"; }, 1200);
  });
  return el("div", { class: "esc" }, [head, body]);
}

/* ---- render the consensus tally ----------------------------------------- */
function renderResult(result, q) {
  clear(out);
  const sources = Array.isArray(result.sources) ? result.sources : [];
  const errs = Array.isArray(result.errors) ? result.errors : [];
  const cls = toneClass(result.tone);
  const flagged = Number(result.flagged ?? 0), consulted = Number(result.consulted ?? 0);
  const checked = String(result.checked_at ?? "").replace("T", " ").slice(0, 16);

  // header: N / M flagged, colored by the ratio, + the §2 headline
  const head = el("div", { class: "vhead" }, [
    el("span", { class: `tally-num tone-${cls}`, text: `${flagged} / ${consulted}` }),
    el("span", { class: "tally-tag", text: "flagged" }),
  ]);
  if (result.partial) head.appendChild(el("span", { class: "partial", text: "partial" }));
  head.appendChild(el("span", {
    class: "vmeta",
    text: `${consulted} consulted${checked ? " · " + checked + " UTC" : ""}`,
  }));
  out.appendChild(head);
  out.appendChild(el("div", { class: "thead", text: tallyHeadline(flagged, consulted) }));

  // one attributed row per source
  sources.forEach(s => out.appendChild(sourceRow(s)));

  // errors — named, never hidden
  if (errs.length) {
    out.appendChild(el("div", { class: "gaps" }, [
      el("div", { class: "l", text: "Not consulted — named, never hidden" }),
      el("div", {
        class: "v",
        text: errs.map(e => `${e.source} — not consulted (${e.reason})`).join(" · "),
      }),
    ]));
  }

  // the escalation card, always — the owner wants a one-click copy into email
  out.appendChild(escalationCard(result));
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
