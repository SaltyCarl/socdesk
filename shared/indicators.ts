// indicators.ts — the pure indicator logic shared by the extension's service
// worker, the popup, and the options page. No DOM, no chrome.* — just string
// classification and URL hygiene, so it imports cleanly into an MV3 module
// service worker AND an extension page (and, in a later phase, the web app).
//
// Moved out of extension/lib/indicators.js into shared/ so BOTH surfaces consume
// ONE source (no drift), reachable as `@socdesk/shared/indicators`.
//
// Kept deliberately in lockstep with the site's site/js/data.js so a lookup from
// the extension resolves to exactly the same type the full report would.

/** Every indicator class the type-detector can return. `""` means unclassified. */
export type IndicatorType =
  | 'ipv4'
  | 'domain'
  | 'url'
  | 'md5'
  | 'sha1'
  | 'sha256'
  | 'cve'
  | 'email'
  | ''

/** The subset /api/enrich can actually score — an enrichable indicator. */
export type EnrichableType = 'ipv4' | 'domain' | 'url' | 'md5' | 'sha1' | 'sha256'

/** The six types /api/enrich can actually score. cve + email are NOT here —
 *  they route to the full report instead. `kind:"context"` rows in a response
 *  (ipinfo geo) are context, never a verdict; the popup renders them as such. */
export const ENRICHABLE: ReadonlySet<string> = new Set([
  'ipv4',
  'domain',
  'url',
  'md5',
  'sha1',
  'sha256',
])
export const isEnrichable = (t: string): t is EnrichableType => ENRICHABLE.has(t)

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[a-z]{2,}$/i

/** Classify a refanged indicator. Returns "" when nothing matches.
 *  Order matters: hash lengths before domain, url before bare domain. */
export function detectType(q: string): IndicatorType {
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(q)) return 'ipv4'
  if (/^[a-f0-9]{64}$/i.test(q)) return 'sha256'
  if (/^[a-f0-9]{40}$/i.test(q)) return 'sha1'
  if (/^[a-f0-9]{32}$/i.test(q)) return 'md5'
  if (/^cve-\d{4}-\d{4,7}$/i.test(q)) return 'cve'
  if (EMAIL_RE.test(q)) return 'email'
  if (/^https?:\/\//i.test(q)) return 'url'
  if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(q)) return 'domain'
  return ''
}

/** Refang analyst-pasted indicators: evil[.]com, hxxp://, 1.2.3[.]4, a[at]b. */
export const refang = (s: unknown): string =>
  String(s ?? '')
    .trim()
    .replace(/\[\.\]|\(\.\)|\{\.\}/g, '.')
    .replace(/\[:\]/g, ':')
    .replace(/\bhxxp/gi, 'http')
    .replace(/\[at\]/gi, '@')

/** Only http/https URLs survive; everything else (javascript:, data:, garbage)
 *  becomes "" so an attacker-influenced source.url can never build a live href.
 *  Returns the parsed absolute URL string, safe to assign to an anchor .href. */
export function safeUrl(u: unknown): string {
  try {
    const p = new URL(String(u ?? ''))
    return p.protocol === 'https:' || p.protocol === 'http:' ? p.href : ''
  } catch {
    return ''
  }
}

/** The SOCDesk instance the extension talks to. Self-hosters override it in
 *  Options; anything unparseable falls back to the canonical origin. Path,
 *  query and hash are stripped so we always hold a bare origin. */
export const DEFAULT_ORIGIN = 'https://socdesk.io'
export function normalizeOrigin(value: unknown): string {
  const raw = String(value ?? '').trim()
  if (!raw) return DEFAULT_ORIGIN
  try {
    const u = new URL(raw)
    if (u.protocol !== 'https:' && u.protocol !== 'http:') return DEFAULT_ORIGIN
    return u.origin
  } catch {
    return DEFAULT_ORIGIN
  }
}

/** Full-report deep link. The indicator rides in the URL *fragment*, exactly
 *  like the site's bookmarklet: fragments never leave the browser, so the host
 *  never sees the value on the initial navigation. */
export const reportUrl = (origin: unknown, q: string): string =>
  `${normalizeOrigin(origin)}/#q=${encodeURIComponent(q)}`

/** The live enrichment endpoint URL for a classified indicator. */
export const enrichUrl = (origin: unknown, type: string, q: string): string =>
  `${normalizeOrigin(origin)}/api/enrich?type=${encodeURIComponent(type)}` +
  `&q=${encodeURIComponent(q)}`
