// GET /api/enrich?type=<ipv4|domain|url|md5|sha1|sha256>&q=<indicator>
//
// Same-origin by design: this is a Pages Function on the site's own domain, so
// the CSP keeps `connect-src 'self'` and the browser never talks to a third
// party the analyst did not choose. A separate api.* origin would have cost a
// CSP exception, a CORS layer, and a second deploy for nothing.
//
// The keys live in Pages project secrets and never reach the browser. That is
// the entire reason this file exists rather than the site calling the
// reputation APIs directly.
import { enrich, _internals } from "../../lib/enrich.mjs";
import { ipDecision } from "../../lib/enrich/ratelimit.mjs";
import {
  BUDGETS, budgetBlockedSet, dispatchedBudgetKeys, shouldFlush, budgetKey, BUDGET_TTL_S,
} from "../../lib/enrich/budgets.mjs";

// L1 — in-isolate per-IP soft latch (§11.1). ZERO KV: these live only in this
// isolate's memory; the WAF Block rule is the distributed-flood shield.
const ipWindow = new Map();   // ip -> { windowStart, count }
const ipLatched = new Map();  // ip -> latchedUntilMs

// L2 — per-isolate budget buffer for coalesced KV writes.
// `budget:<key>:<utcday>` -> { base, pending }
const budgetBuf = new Map();

// Per-isolate memo of the committed community dataset. Caches ONLY successful
// loads — a transient miss returns null WITHOUT poisoning the cache, so the
// next request retries instead of omitting community rows for the isolate's
// whole life (Infra review). No D1: this reads a static asset (Option A
// invariant — /api/enrich gains no DB binding).
let _communityCache;
export async function loadCommunity(env, origin) {
  if (_communityCache !== undefined) return _communityCache;   // success previously memoized
  try {
    const req = new Request(`${origin}/data/state/community_reports.json`);
    const res = env.ASSETS ? await env.ASSETS.fetch(req) : await fetch(req);
    if (res.ok) { _communityCache = await res.json(); return _communityCache; }
  } catch { /* fall through — transient miss, not memoized */ }
  return null;                                                  // retried next request
}

const json = (body, status = 200, extra = {}) => new Response(
  JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      // The verdict is about the indicator, never about who asked. Nothing
      // here is per-user, so a shared cache is safe and halves upstream load.
      "cache-control": "public, max-age=900",
      "x-content-type-options": "nosniff",
      ...extra,
    },
  });

// L1: pure decision + isolate Maps. Returns true when the IP is rate-limited.
// No attributable IP → never limited.
function rateLimited(ip, nowMs) {
  if (!ip) return false;
  const st = ipWindow.get(ip) || { windowStart: 0, count: 0 };
  const d = ipDecision({ now: nowMs, windowStart: st.windowStart, count: st.count, latchedUntil: ipLatched.get(ip) || 0 });
  ipWindow.set(ip, { windowStart: d.newWindowStart, count: d.newCount });
  if (d.newLatchedUntil) ipLatched.set(ip, d.newLatchedUntil);
  return !d.allow;
}

// L2 read: build the budgetBlocked Set from in-isolate effective counts
// (base = last KV read, refreshed at flush; + pending). One KV read per budgeted
// key per isolate per day. Ships dark + fail-open: no KV, or a throwing get, ⇒
// empty set ⇒ every source eligible.
async function readBudgetBlocked(env, type, now) {
  if (!env.KV) return new Set();
  const counts = {};
  for (const s of _internals.SOURCES) {
    if (BUDGETS[s.key] === undefined || !s.types.includes(type)) continue;
    const k = budgetKey(s.key, now);
    let buf = budgetBuf.get(k);
    if (!buf) {
      let base = 0;
      try { base = Number(await env.KV.get(k)) || 0; } catch { base = 0; }
      buf = { base, pending: 0 };
      budgetBuf.set(k, buf);
    }
    counts[s.key] = buf.base + buf.pending;
  }
  return budgetBlockedSet(counts, BUDGETS);
}

// L2 flush: read-modify-write ONE key (§4.2 "read → put(current + pending) →
// reset"). Fail-open: on error keep the delta for a later attempt, never throw.
async function flushBudgetKey(env, k, buf) {
  const pending = buf.pending;
  buf.pending = 0;                                     // reset first: concurrent requests won't double-count
  try {
    const cur = Number(await env.KV.get(k)) || buf.base;
    const next = cur + pending;
    await env.KV.put(k, String(next), { expirationTtl: BUDGET_TTL_S });
    buf.base = next;
  } catch {
    buf.pending += pending;                            // restore the unflushed delta
  }
}

// L2 count: increment ONLY dispatched budgeted sources (§11.2), coalesced. The
// flush never blocks the response (waitUntil when available).
async function countBudgets(env, type, envForPlan, budgetBlocked, now, waitUntil) {
  if (!env.KV) return;
  const keys = dispatchedBudgetKeys({ type, env: envForPlan, budgetBlocked, sources: _internals.SOURCES, budgets: BUDGETS });
  for (const key of keys) {
    const k = budgetKey(key, now);
    const buf = budgetBuf.get(k) || { base: 0, pending: 0 };
    buf.pending += 1;
    budgetBuf.set(k, buf);
    if (shouldFlush({ pending: buf.pending, base: buf.base, budget: BUDGETS[key] })) {
      const p = flushBudgetKey(env, k, buf);
      if (waitUntil) waitUntil(p); else await p;
    }
  }
}

export async function onRequestGet({ request, env, waitUntil }) {
  const url = new URL(request.url);
  const type = (url.searchParams.get("type") || "").toLowerCase();
  const q = url.searchParams.get("q") || "";

  // Cloudflare's edge cache, keyed by the normalised request URL. Free, and it
  // needs no KV namespace binding — one less thing to configure by hand.
  const cache = caches.default;
  const key = new Request(`${url.origin}/api/enrich?type=${encodeURIComponent(type)}` +
                          `&q=${encodeURIComponent(q)}`, request);
  const hit = await cache.match(key);
  if (hit) return hit;                       // cache hit → makes no upstream call → never rate-limited/budgeted

  // L1: in-isolate per-IP latch, applied ONLY after a cache miss (§4.1, §11.1).
  const ip = request.headers.get("CF-Connecting-IP") || "";
  const nowMs = Date.now();
  if (rateLimited(ip, nowMs))
    return json({ error: "rate", reason: "slow down" }, 429, { "cache-control": "no-store" });

  const now = new Date(nowMs);
  const community = await loadCommunity(env, url.origin);
  const envForPlan = { ...env, SOCDESK_COMMUNITY_DATA: community };

  // L2: read budget state → blocked set → inject into the pure assembler.
  const budgetBlocked = await readBudgetBlocked(env, type, now);
  const result = await enrich(fetch, type, q, envForPlan, now, budgetBlocked);
  if (result.error) return json({ error: result.error }, result.status ?? 400);

  // L2: count ONLY dispatched budgeted sources, coalesced (never blocks response).
  await countBudgets(env, type, envForPlan, budgetBlocked, now, waitUntil);

  const res = json(result);
  // Never cache a partial answer (transient failure). A budget skip is
  // blocking:false → partial stays false → the degraded answer still caches.
  if (!result.partial) await cache.put(key, res.clone());
  return res;
}
