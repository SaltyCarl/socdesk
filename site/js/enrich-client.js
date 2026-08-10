// enrich-client.js — the front-end half of the live reputation lookup.
//
// SOCDesk holds no reputation corpus by design (COMPLIANCE.md): the verdict
// engine can only ever answer "NOT IN CORPUS" for an IP, domain, URL or hash.
// The live answer comes from `/api/enrich`, a same-origin Pages Function that
// fans the indicator out across AbuseIPDB / VirusTotal / GreyNoise / ipinfo /
// MalwareBazaar / urlscan and returns one composite (shape defined in
// lib/enrich.mjs). This module calls it, shows a loading state, then renders
// the multi-source verdict and the ready-to-paste evidence card — replacing the
// static "NOT IN CORPUS" placeholder for these types.
//
// CONTRACT WITH THE REST OF THE APP:
//   * Same-origin fetch only — CSP is `connect-src 'self'`; a third-party
//     origin would need a policy exception we deliberately do not grant.
//   * Never blank, never crash. A dead endpoint, a timeout, a validation
//     refusal (private IP) or a non-JSON body all degrade to the static verdict
//     and pivots that are already on screen.
//   * Every upstream string is attacker-influenced (an ISP name, a VT engine
//     result). Escape ALL of it with esc()/safeUrl() at render — same rule the
//     feed renderer lives by.
import { esc, safeUrl, copyToButton } from "./data.js";
import { escalation, download, docketHTML } from "./verdict.js";
import { renderEvidence, copyEvidence, downloadEvidence } from "./evidence.js";
import { decode } from "./motion.js";

const ENRICHABLE = new Set(["ipv4", "domain", "url", "md5", "sha1", "sha256"]);
export const isEnrichable = t => ENRICHABLE.has(t);

// The verdict roll-up is the worst credible answer (lib/enrich.mjs overall()).
// Words are chosen so "benign" is never a clean bill of health and, per the
// design law, gray is unknown and never green.
const TONE = { malicious: "red", suspicious: "orange", benign: "green", unknown: "muted" };
const WORD = {
  malicious: "MALICIOUS", suspicious: "SUSPICIOUS",
  benign: "NO ADVERSE FINDINGS", unknown: "NO DATA ON RECORD",
};
const toneOf = v => TONE[v] ?? "muted";
const wordOf = v => WORD[v] ?? "NO DATA ON RECORD";

// The whole fan-out is bounded server-side (4.5s per upstream, run in
// parallel); give the round-trip generous headroom, then stop waiting so the
// UI never hangs on a wedged edge.
const FETCH_TIMEOUT_MS = 12000;

/**
 * Call the enrichment endpoint. Resolves to a tagged outcome, never throws:
 *   { status:"ok", result }         a composite with a `sources` array
 *   { status:"declined", reason }   the endpoint refused the indicator (400)
 *   { status:"unavailable", reason} network / timeout / HTTP / parse failure
 * `fetchImpl` is injectable for tests; production passes the real fetch.
 */
export async function fetchEnrich(type, q, { timeoutMs = FETCH_TIMEOUT_MS, fetchImpl } = {}) {
  const f = fetchImpl || ((...a) => fetch(...a));
  const url = `/api/enrich?type=${encodeURIComponent(type)}&q=${encodeURIComponent(q)}`;
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const r = await f(url, { signal: ctrl.signal, headers: { accept: "application/json" } });
    let body = null;
    try { body = await r.json(); } catch { /* served a non-JSON error body */ }
    if (r.ok && body && Array.isArray(body.sources)) return { status: "ok", result: body };
    // A 400 from lib/enrich.mjs carries a human reason (private IP, malformed).
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

/* ---------- render helpers (every dynamic string escaped) ---------------- */

function factsHTML(facts) {
  const rows = (facts ?? []).filter(([, v]) => v && v !== "—");
  if (!rows.length) return "";
  return `<div class="ev">${rows.map(([k, v]) =>
    `<div class="ev-row"><span class="k">${esc(k)}</span><span class="d">${esc(v)}</span></div>`
  ).join("")}</div>`;
}

function sourceBlockHTML(s) {
  const context = s.kind === "context";
  const v = String(s.verdict ?? "unknown").toLowerCase();
  const tag = context ? "CONTEXT" : (WORD[v] ? v.toUpperCase() : "UNKNOWN");
  const tagTone = context ? "muted" : toneOf(v);
  const href = safeUrl(s.url);
  const shot = safeUrl(s.screenshot);
  const verify = href
    ? `<a class="pivot src-verify" href="${href}" target="_blank" rel="noopener noreferrer">Verify at ${esc(s.name)} ↗</a>`
    : "";
  const preview = shot
    ? `<a class="pivot src-verify" href="${shot}" target="_blank" rel="noopener noreferrer">Screenshot ↗</a>`
    : "";
  return `
    <div class="src-block">
      <div class="src-h">
        <span class="src-name">${esc(s.name)}</span>
        <span class="tag tone-${tagTone}">${esc(tag)}</span>
      </div>
      <div class="src-headline">${esc(s.headline ?? "")}</div>
      ${factsHTML(s.facts)}
      ${verify || preview ? `<div class="src-links">${verify}${preview}</div>` : ""}
    </div>`;
}

function notConsultedHTML(errors) {
  const rows = (errors ?? []).map(e => `${e.source} (${e.reason})`);
  if (!rows.length) return "";
  return `<div class="ev"><div class="l">Not consulted — named, never hidden</div>
    <div class="live-gaps mono">${esc(rows.join(" · "))}</div></div>`;
}

function noteHTML(head, tone, body) {
  return `<div class="vc-head"><span class="caps tone-${tone}">${esc(head)}</span></div>
    <div class="live-note">${esc(body)}</div>`;
}

/** Replace the static router headline + on-screen docket so the console no
 *  longer contradicts the live answer, and re-point the copy/download controls
 *  at an escalation that carries the live findings. */
function replaceStatic(consoleEl, staticVerdict, result, word, tone) {
  const vword = consoleEl.querySelector("#vword");
  if (vword) {
    vword.className = `verdict-word tone-${tone}`;
    decode(vword, word, .45);
  }
  const caps = consoleEl.querySelector(".vc-head .caps");   // static header is first in DOM order
  if (caps) { caps.className = `caps tone-${tone}`; caps.textContent = `Live verdict · ${staticVerdict.type}`; }
  const basis = consoleEl.querySelector(".vc-basis");
  if (basis) basis.textContent =
    `Composite of ${result.sources.length} public reputation source` +
    `${result.sources.length === 1 ? "" : "s"}, each linked below for verification. ` +
    `SOCDesk mirrors none of it — the escalation card is built from their own words.`;

  // A live-aware verdict object so the copied escalation and the on-screen
  // docket state the live assessment, with each source's line as public data.
  const evidence = result.sources
    .filter(s => s.kind !== "context")
    .map(s => [s.name, s.headline])
    .concat((result.errors ?? []).map(e => [e.source, `not consulted (${e.reason})`]));
  const v2 = { ...staticVerdict, word, tone, score: null, basis: basis?.textContent ?? staticVerdict.basis, evidence };

  const escBody = consoleEl.querySelector("#escBody");
  if (escBody) escBody.innerHTML = docketHTML(v2);
  consoleEl.querySelectorAll("[data-esc]").forEach(b => b.onclick = () => {
    const mode = b.dataset.esc, was = b.textContent;
    const text = escalation(v2, { markdown: mode !== "txt" });
    if (mode === "dl") return download(`escalation-${v2.q}.md`, text, "text/markdown");
    copyToButton(b, text, was);
  });
}

async function renderResult(consoleEl, box, staticVerdict, result) {
  const word = wordOf(result.verdict), tone = toneOf(result.verdict);
  const checked = String(result.checked_at ?? "").replace("T", " ").slice(0, 16) + " UTC";
  const n = result.sources.length;

  box.innerHTML = `
    <div class="vc-head">
      <span class="caps tone-${tone}">Live reputation · ${esc(staticVerdict.type)}</span>
      <span class="live-status mono">${esc(n)} source${n === 1 ? "" : "s"} · ${esc(checked)}</span>
    </div>
    <div class="live-verdict">
      <span class="verdict-word tone-${tone}">${esc(word)}</span>
      ${result.partial ? `<span class="live-partial mono">partial — one or more sources unavailable</span>` : ""}
    </div>
    ${result.sources.map(sourceBlockHTML).join("")}
    ${notConsultedHTML(result.errors)}
    <div class="evcard">
      <div class="evcard-h">
        <span class="caps">Escalation card — paste straight into the ticket</span>
        <span class="live-acts">
          <button class="act" data-ev="copy">Copy image</button>
          <button class="act" data-ev="png">Download PNG</button>
        </span>
      </div>
      <div class="evcard-body" id="evCardBody"></div>
    </div>`;

  replaceStatic(consoleEl, staticVerdict, result, word, tone);

  // Fonts must be resolved before the canvas is painted or it substitutes a
  // fallback face and the card looks nothing like the site (evidence.js).
  try { await (document.fonts?.ready ?? Promise.resolve()); } catch { /* no-op */ }
  if (!box.isConnected) return;
  let canvas;
  try { canvas = renderEvidence(result); } catch { /* fall through: skip the image */ }
  const holder = box.querySelector("#evCardBody");
  if (canvas && holder) {
    canvas.className = "evcard-canvas";
    holder.appendChild(canvas);
    box.querySelector('[data-ev="copy"]').onclick = async e => {
      const b = e.currentTarget, was = b.textContent;
      b.textContent = (await copyEvidence(canvas)) ? "COPIED ✓" : "COPY BLOCKED";
      setTimeout(() => { b.textContent = was; }, 1200);
    };
    box.querySelector('[data-ev="png"]').onclick = () => downloadEvidence(canvas, result.indicator);
  } else if (holder) {
    holder.innerHTML = `<div class="live-note">Evidence image unavailable in this browser —
      the source findings above carry every figure and its link.</div>`;
  }
}

/**
 * Entry point. Renders into #liveEnrich inside the verdict console:
 * a loading state, then the live verdict + evidence card, or an honest
 * degraded note that leaves the static verdict and pivots untouched.
 */
export async function enrichInto(consoleEl, { type, indicator, verdict }, opts = {}) {
  if (!consoleEl || !isEnrichable(type)) return;
  consoleEl.querySelector("#liveEnrich")?.remove();      // drop a prior lookup's section

  const box = document.createElement("section");
  box.id = "liveEnrich";
  box.className = "live";
  box.setAttribute("aria-live", "polite");
  box.innerHTML = `
    <div class="vc-head">
      <span class="caps tone-accent">Live reputation · ${esc(verdict.type)}</span>
      <span class="live-status mono"><span class="ping" aria-hidden="true"></span>Checking public reputation sources…</span>
    </div>`;
  consoleEl.appendChild(box);

  const out = await fetchEnrich(type, indicator, opts);
  if (!box.isConnected) return;                          // a newer lookup cleared us

  if (out.status === "ok") return renderResult(consoleEl, box, verdict, out.result);
  if (out.status === "declined")
    return void (box.innerHTML = noteHTML("Live enrichment declined", "muted",
      `${out.reason}. The static verdict and pivots above still apply.`));
  return void (box.innerHTML = noteHTML("Live reputation unavailable", "muted",
    `${out.reason} — showing the static verdict and pivots above. Use the pivot ` +
    `links to check reputation directly.`));
}
