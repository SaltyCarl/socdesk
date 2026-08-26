// GET /api/favicon?d=<domain>
//
// Same-origin favicon proxy for the claimed-victim list. The client renders
// `<img src="/api/favicon?d=<domain>">`, so the page CSP stays `img-src 'self'`
// and the analyst's browser NEVER contacts a third-party icon CDN — which victim
// domains an analyst is viewing never leak to DuckDuckGo (the edge fetches the
// icon, not the analyst's IP/session). Mirrors functions/api/enrich.js: a
// same-origin Pages Function is why the tight CSP survives.
//
// On ANY failure — bad domain, upstream error, non-image, empty body — we return
// a 1x1 transparent PNG (HTTP 200), so the <img> never renders a broken-image
// glyph and the client's onError swaps in a monogram cleanly.

import { ipDecision } from "../../lib/enrich/ratelimit.mjs";

// L1 — in-isolate per-IP soft latch, mirroring enrich.js. ZERO KV: lives only
// in this isolate's memory. Applied after a cache MISS (a hit costs no upstream
// fetch), so a flood of unique domains can't drive unbounded DuckDuckGo fetches.
const ipWindow = new Map(); // ip -> { windowStart, count }
const ipLatched = new Map(); // ip -> latchedUntilMs
function rateLimited(ip, nowMs) {
  if (!ip) return false;
  const st = ipWindow.get(ip) || { windowStart: 0, count: 0 };
  const d = ipDecision({ now: nowMs, windowStart: st.windowStart, count: st.count, latchedUntil: ipLatched.get(ip) || 0 });
  ipWindow.set(ip, { windowStart: d.newWindowStart, count: d.newCount });
  if (d.newLatchedUntil) ipLatched.set(ip, d.newLatchedUntil);
  return !d.allow;
}

// A real favicon is a few KB; cap the proxied body so a hostile/oversized
// upstream response can't balloon isolate memory. Read is bounded even when the
// upstream omits or lies about content-length.
const MAX_ICON_BYTES = 262144; // 256 KB
async function readCapped(upstream) {
  const declared = Number(upstream.headers.get("content-length") || 0);
  if (declared > MAX_ICON_BYTES) return null; // honest-large: reject before reading
  if (!upstream.body) return null;
  const reader = upstream.body.getReader();
  const chunks = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > MAX_ICON_BYTES) {
      await reader.cancel();
      return null; // over cap (or a lying content-length) → treat as no icon
    }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.byteLength;
  }
  return out;
}

// 1x1 transparent PNG — the honest "no icon" answer.
const BLANK_PNG = Uint8Array.from(
  atob(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==",
  ),
  (c) => c.charCodeAt(0),
);

function blank() {
  return new Response(BLANK_PNG, {
    status: 200,
    headers: {
      "content-type": "image/png",
      // Short cache: a miss now (cold DNS / CDN warm-up) may resolve later, so
      // don't pin the blank for a week the way a real hit is pinned.
      "cache-control": "public, max-age=3600",
      "x-content-type-options": "nosniff",
    },
  });
}

// Bare hostname only: lowercase labels, >=1 dot, <=253 chars, no scheme / path /
// port / userinfo. This is what keeps the server-side fetch pinned to the icon
// service — a value that could redirect it elsewhere is rejected to the blank.
const HOST_RE =
  /^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;

export async function onRequestGet({ request }) {
  const url = new URL(request.url);
  const domain = (url.searchParams.get("d") || "").trim().toLowerCase();
  if (!HOST_RE.test(domain)) return blank();

  // Cloudflare's edge cache, keyed by the normalised domain. A shared hit means
  // most views never touch the upstream at all — privacy AND rate. Needs no KV
  // binding (mirrors enrich.js).
  const cache = caches.default;
  const key = new Request(`${url.origin}/api/favicon?d=${encodeURIComponent(domain)}`, request);
  const hit = await cache.match(key);
  if (hit) return hit;

  // Rate-limit only cache MISSES — a hit never touches the upstream. A local
  // flood gets a silent blank (the client just shows a monogram); no challenge.
  if (rateLimited(request.headers.get("cf-connecting-ip") || "", Date.now())) return blank();

  let upstream;
  try {
    upstream = await fetch(`https://icons.duckduckgo.com/ip3/${domain}.ico`, {
      // Never forward the viewer's headers/cookies to the third party.
      headers: { accept: "image/*" },
      cf: { cacheTtl: 604800, cacheEverything: true },
    });
  } catch {
    return blank();
  }

  const ct = upstream.headers.get("content-type") || "";
  if (!upstream.ok || !ct.startsWith("image/")) return blank();

  const body = await readCapped(upstream);
  // DuckDuckGo answers unknown domains with a placeholder too; treat an empty
  // body (or an over-cap/oversized one → null) as a miss rather than serving it.
  if (!body || body.byteLength === 0) return blank();

  const res = new Response(body, {
    status: 200,
    headers: {
      "content-type": ct,
      // The icon for a domain doesn't change per viewer, so a long shared cache
      // is safe and slashes upstream load.
      "cache-control": "public, max-age=604800, immutable",
      "x-content-type-options": "nosniff",
    },
  });
  await cache.put(key, res.clone());
  return res;
}
