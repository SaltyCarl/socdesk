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
import { enrich } from "../../lib/enrich.mjs";

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

export async function onRequestGet({ request, env }) {
  const url = new URL(request.url);
  const type = (url.searchParams.get("type") || "").toLowerCase();
  const q = url.searchParams.get("q") || "";

  // Cloudflare's edge cache, keyed by the normalised request URL. Free, and it
  // needs no KV namespace binding — one less thing to configure by hand.
  const cache = caches.default;
  const key = new Request(`${url.origin}/api/enrich?type=${encodeURIComponent(type)}` +
                          `&q=${encodeURIComponent(q)}`, request);
  const hit = await cache.match(key);
  if (hit) return hit;

  const community = await loadCommunity(env, url.origin);
  const result = await enrich(fetch, type, q, { ...env, SOCDESK_COMMUNITY_DATA: community });
  if (result.error) return json({ error: result.error }, result.status ?? 400);

  const res = json(result);
  // Never cache a partial answer: a transient upstream failure would otherwise
  // be served as the truth for the next 15 minutes.
  if (!result.partial) await cache.put(key, res.clone());
  return res;
}
