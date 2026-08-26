// format.ts — presentation helpers for the data views.
//
// Ported from site/js/data.js. React escapes text nodes for us, so the site's
// esc()/safeUrl()-as-escaper duties collapse to a single job here: URL
// validation (only http/https hrefs survive) plus freshness + number wording.
// Pure functions, no I/O, no React.

/** Minutes since an ISO timestamp; +Infinity when absent/unparseable. */
export const ageMin = (iso?: string | null): number =>
  iso ? Math.max(0, (Date.now() - Date.parse(iso)) / 60000) : Infinity

/** Coarse "x ago" relative time — the queue's liveness read. */
export function rel(iso?: string | null): string {
  const m = ageMin(iso)
  if (!isFinite(m)) return '—'
  if (m < 1) return 'Now'
  if (m < 60) return `${Math.round(m)}m ago`
  if (m < 1440) return `${Math.round(m / 60)}h ago`
  return `${Math.round(m / 1440)}d ago`
}

/** ISO date, day-precision. */
export const day = (iso?: string | null): string =>
  (iso ?? '').slice(0, 10) || '—'

/** Grouped integer, e.g. 10,193. */
export const num = (n?: number | null): string =>
  (n ?? 0).toLocaleString('en-US')

/** A 0–1 probability as a whole-percent string; em-dash when unknown. */
export const pct = (n?: number | null): string =>
  n == null ? '—' : `${Math.round(n * 100)}%`

/** A URL safe to render as a live href; returns '' otherwise, so a caller's
 *  `href ? <a> : <span>` degrades to plain text. Two rejections:
 *   - non-http(s) schemes — never emit a `javascript:`/`data:` href; and
 *   - `.onion` hosts — Tor leak-site infrastructure SOCDesk never hyperlinks
 *     (a live link one-clicks an analyst onto criminal infra and reads as
 *     endorsement; `.onion` is `http://`, so a scheme-only check let it slip
 *     through — the Feed leak this closes). The `.onion` STRING is still kept
 *     as attributed plain-text provenance (Intel profile, claimedVictims); this
 *     guard only stops it becoming a link. Centralised on purpose: every current
 *     AND future caller degrades uniformly, so the per-surface leak can't recur. */
export function safeUrl(u?: string | null): string {
  try {
    const p = new URL(String(u ?? ''))
    if (p.protocol !== 'http:' && p.protocol !== 'https:') return ''
    if (p.hostname.toLowerCase().endsWith('.onion')) return ''
    return p.href
  } catch {
    return ''
  }
}

/** Slug → words: core_privileged_access → "core privileged access". */
export const humanize = (s?: string | null): string =>
  (s ?? '').replace(/[_-]+/g, ' ').trim()

/* ---------------- tone helpers (Tailwind classes, verdict-reserved) ------- *
 * Verdict red/amber/green carry MEANING only. For the feed's priority score
 * that meaning is "how urgently should an analyst look" — a severity read, so
 * the reserved hues are legitimate. Green is withheld: a low-priority item is
 * not "benign/safe", it is merely lower in the queue, so it stays neutral.    */

export function scoreTextTone(s?: number | null): string {
  if (s == null) return 'text-faint'
  if (s >= 80) return 'text-verdict-red'
  if (s >= 60) return 'text-verdict-amber'
  if (s >= 40) return 'text-paper'
  return 'text-muted'
}

/** CVSS qualitative severity → chip skin. critical=red, high=amber; medium/low
 *  stay neutral ink (a MEDIUM CVE is context, not "benign", so never green). */
export type SeverityKey = 'critical' | 'high' | 'medium' | 'low' | 'unknown'

export function severityKey(s?: string | null): SeverityKey {
  const v = (s ?? '').toLowerCase()
  if (v === 'critical' || v === 'high' || v === 'medium' || v === 'low') return v
  return 'unknown'
}
