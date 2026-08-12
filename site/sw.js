/* SOCDESK service worker — offline capability for the static tier.
 *
 * Strategy is split deliberately:
 *   shell (html/css/js/fonts) → cache-first, because it changes only on deploy
 *   data (data/*.json)        → network-first with cache fallback, because
 *                               stale intel presented as fresh is the one
 *                               failure mode this project cannot have
 * The page reads the cached response's Date header to tell the analyst exactly
 * how old the data is (see app.js). Never silently serve stale data as live.
 */
// BUMP THIS on every change to the shell (html/css/js). The shell is cached
// cache-first, so without a bump returning visitors keep the old UI after a
// deploy — this masked two changes during development before it was caught.
const VERSION = "socdesk-v18";  // v18: escalation = geo-led image card (Copy card +
                                // Copy text); text docket CVE-only; .live layout collision fixed
                                // v17: interactive cobe globe in the home hero
                                // (js/globe.js + js/vendor/cobe.js + css/globe.css)
                                // v16: SD-monogram logo (topbar sdmark + favicon)
                                // replaces the pixel coffee-mug. v15: hero H1 stacked + periwinkle OSINT, "Intelligence summary" label. v14: hero declutter — Live-wire ticker cut,
                                // H1 → "IOC in. OSINT out." (lede removed), TRY
                                // example chips dropped, disclosure collapsed to
                                // one line (clear-analyst-state control kept)
                                // v13: RADAR re-LAYOUT — masthead cut, search-hero
                                // triage home, feed-scoped ticker/band, gauge value
                                // centred in the ring, escalation-card language on
                                // the console docket + feed rows + actor cards,
                                // stronger-contrast pixel mug + unified favicon
                                // v12: RADAR warm-espresso/warm-paper restyle —
                                // dual-theme tokens (periwinkle accent), pixFrontal
                                // topbar mug, Light/Dark/System toggle
                                // v11: consensus-tally verdict model — /api/enrich
                                // returns N/M + tone (no single-word verdict);
                                // gauge + attributed breakdown + §4 escalation
                                // v10: live /api/enrich wired into the verdict
                                // console (enrich-client.js) + tagline decode
                                // never strands gibberish
                                // v9: pivot diet — T1 workflow vendors only
                                // v8: RELATED entity block (relations.json wired)
                                // v7: escalation evidence card
                                // v6: Cloudflare Pages host, socdesk.io URLs
                                // v5: bookmarklet install card
                                // v4: operational console layout (view
                                // switching, verdict console, work-queue feed)
const SHELL = `${VERSION}-shell`;
const DATA = `${VERSION}-data`;

const SHELL_ASSETS = [
  "./", "./index.html",
  "./css/tokens.css", "./css/base.css", "./css/chrome.css", "./css/panels.css",
  "./css/globe.css",
  "./js/app.js", "./js/data.js", "./js/state.js", "./js/motion.js",
  "./js/verdict.js", "./js/views.js", "./js/bookmarklet.js", "./js/evidence.js",
  "./js/related.js", "./js/enrich-client.js", "./js/globe.js", "./js/vendor/cobe.js",
  "./js/toolbelt/tools.js", "./js/toolbelt/belt.js",
];

self.addEventListener("install", e => {
  e.waitUntil((async () => {
    const c = await caches.open(SHELL);
    // addAll is atomic — one 404 would fail the whole install, so add
    // individually and tolerate misses.
    await Promise.all(SHELL_ASSETS.map(u => c.add(u).catch(() => {})));
    self.skipWaiting();
  })());
});

self.addEventListener("activate", e => {
  e.waitUntil((async () => {
    const keys = await caches.keys();
    await Promise.all(keys.filter(k => !k.startsWith(VERSION)).map(k => caches.delete(k)));
    await self.clients.claim();
  })());
});

self.addEventListener("fetch", e => {
  const { request } = e;
  if (request.method !== "GET") return;
  const url = new URL(request.url);
  if (url.origin !== self.location.origin) return;      // never touch CDNs

  // Dynamic endpoints (the /api/enrich reputation fan-out) are per-indicator and
  // set their own cache policy — never shell-cache them, and never let the
  // offline index.html fallback below answer an API call with a page of HTML.
  if (url.pathname.startsWith("/api/")) return;

  if (url.pathname.includes("/data/")) {
    e.respondWith((async () => {
      try {
        const fresh = await fetch(request);
        if (fresh.ok) (await caches.open(DATA)).put(request, fresh.clone());
        return fresh;
      } catch {
        const hit = await caches.match(request);
        if (hit) return hit;
        return new Response(JSON.stringify({ __offline: true }),
          { status: 503, headers: { "Content-Type": "application/json" } });
      }
    })());
    return;
  }

  e.respondWith((async () => {
    const hit = await caches.match(request);
    if (hit) return hit;
    try {
      const fresh = await fetch(request);
      if (fresh.ok && url.pathname.match(/\.(css|js|html)$/))
        (await caches.open(SHELL)).put(request, fresh.clone());
      return fresh;
    } catch {
      return caches.match("./index.html");
    }
  })());
});
