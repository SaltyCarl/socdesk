// logo.ts — pure helpers for the claimed-victim org-logo treatment.
//
// A victim row shows the org's real favicon when we can resolve one, else a
// brand-coloured monogram. The favicon is fetched through OUR OWN same-origin
// proxy (/api/favicon, functions/api/favicon.js) so the page CSP stays
// `img-src 'self'` and the analyst's browser never reveals which victim domains
// they are viewing to a third-party icon CDN. No React, no I/O — unit-tested in
// a plain env (see __tests__/logo.test.ts).

/** Bare-hostname shape: lowercase labels, >=1 dot, no scheme / path / port /
 *  userinfo. A mirror of the server-side guard in functions/api/favicon.js — a
 *  value that fails here yields no <img> at all (the caller renders a monogram),
 *  so a malformed domain never becomes a request. */
const HOST_RE =
  /^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/

/** Same-origin favicon URL for a victim domain, or null when the domain is
 *  absent / malformed (the caller renders a monogram instead). Never returns a
 *  third-party URL — the proxy is the whole reason the CSP can stay tight. */
export function faviconSrc(domain?: string | null): string | null {
  const d = (domain ?? '').trim().toLowerCase()
  if (!HOST_RE.test(d)) return null
  return `/api/favicon?d=${encodeURIComponent(d)}`
}

/** A 1–2 letter monogram from an org name — the initials of its first two
 *  words, uppercased; a single word collapses to its first two letters; an
 *  empty name falls back to '?'. Deterministic, punctuation-insensitive. */
export function monogram(name?: string | null): string {
  const words = (name ?? '').split(/[^A-Za-z0-9]+/).filter(Boolean)
  if (words.length >= 2) return (words[0][0] + words[1][0]).toUpperCase()
  if (words.length === 1) return words[0].slice(0, 2).toUpperCase()
  return '?'
}
