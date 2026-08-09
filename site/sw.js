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
const VERSION = "socdesk-v4";   // v4: operational console layout (view
                                // switching, verdict console, work-queue feed)
const SHELL = `${VERSION}-shell`;
const DATA = `${VERSION}-data`;

const SHELL_ASSETS = [
  "./", "./index.html",
  "./css/tokens.css", "./css/base.css", "./css/chrome.css", "./css/panels.css",
  "./js/app.js", "./js/data.js", "./js/state.js", "./js/motion.js",
  "./js/verdict.js", "./js/views.js",
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
