// sw.js — TOMBSTONE.
//
// The legacy vanilla site/ registered a cache-first service worker
// (socdesk-v19) at scope '/'. The new React app ships no service worker, but a
// 404 on /sw.js does NOT unregister the old one — per the SW spec the existing
// registration is retained, so returning visitors (bookmarks, recruiters) would
// stay pinned to the stale cached legacy shell forever.
//
// This byte-different script is served at the SAME /sw.js path, so the browser's
// update check picks it up, and on activate it: clears every cache, unregisters
// itself, and reloads any open clients onto the fresh app. After it runs once,
// no service worker controls the origin.
//
// There is intentionally NO fetch handler — every request goes straight to the
// network (the new app), never a cache.

self.addEventListener('install', () => {
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    (async () => {
      try {
        const keys = await caches.keys();
        await Promise.all(keys.map((k) => caches.delete(k)));
      } catch (e) {
        /* best-effort cache purge */
      }
      try {
        await self.registration.unregister();
      } catch (e) {
        /* best-effort unregister */
      }
      try {
        const clients = await self.clients.matchAll({ type: 'window' });
        for (const client of clients) {
          client.navigate(client.url);
        }
      } catch (e) {
        /* best-effort reclaim */
      }
    })(),
  );
});
