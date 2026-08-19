import type { IndicatorType } from './types'
import { detectType } from '@socdesk/shared/indicators'

/**
 * Lightweight indicator classifier for the palette's live badge. Delegates
 * ALL shape-detection to the shared `detectType` (the same classifier the
 * cockpit's data-boundary check and useLookup use) so the palette can never
 * drift from the rest of the app again (design spec §2.2, §3.2). This
 * function only maps detectType's richer taxonomy onto the palette's badge
 * enum — it adds no detection logic of its own.
 */

const TYPE_MAP: Record<string, IndicatorType> = {
  ipv4: 'ip',
  ipv6: 'ip',
  domain: 'domain',
  url: 'url',
  md5: 'hash',
  sha1: 'hash',
  sha256: 'hash',
  cve: 'cve',
  email: 'unknown', // no palette badge for email — not part of this taxonomy
  '': 'unknown',
}

export function classifyIndicator(raw: string): IndicatorType {
  const s = raw.trim()
  if (!s) return 'unknown'
  return TYPE_MAP[detectType(s)] ?? 'unknown'
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
