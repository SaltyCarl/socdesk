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

  const body = await upstream.arrayBuffer();
  // DuckDuckGo answers unknown domains with a placeholder too; treat an empty
  // body as a miss rather than caching a zero-byte "icon".
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
