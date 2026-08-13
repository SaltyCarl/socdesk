import type { IndicatorType } from './types'

/**
 * Lightweight, dependency-free indicator classifier. Deterministic and
 * cheap — it runs on every keystroke to badge the live query. It is
 * intentionally permissive (a triage hint, not a validator); the real
 * enrichment layer owns strict parsing.
 */

const HEX = /^[a-f0-9]+$/i

export function classifyIndicator(raw: string): IndicatorType {
  const s = raw.trim()
  if (!s) return 'unknown'

  // CVE-YYYY-NNNN(+)
  if (/^cve-\d{4}-\d{3,}$/i.test(s)) return 'cve'

  // MD5 / SHA-1 / SHA-256 by length + hex alphabet
  if ((s.length === 32 || s.length === 40 || s.length === 64) && HEX.test(s)) {
    return 'hash'
  }

  // IPv4 with in-range octets
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(s) && s.split('.').every((o) => Number(o) <= 255)) {
    return 'ip'
  }

  // IPv6 (rough — colon-delimited hex, ≥2 groups)
  if (s.includes(':') && /^[0-9a-f:]+$/i.test(s) && (s.match(/:/g)?.length ?? 0) >= 2) {
    return 'ip'
  }

  // URL — an explicit scheme, or a path component
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(s) || s.includes('/')) return 'url'

  // Bare domain — labels joined by dots with a plausible TLD
  if (
    /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/i.test(s) &&
    /\.[a-z]{2,}$/i.test(s)
  ) {
    return 'domain'
  }

  return 'unknown'
}

/** Short uppercase badge shown on indicator rows. */
export const INDICATOR_LABEL: Record<IndicatorType, string> = {
  ip: 'IP',
  domain: 'DOMAIN',
  url: 'URL',
  hash: 'HASH',
  cve: 'CVE',
  unknown: 'IOC',
}
