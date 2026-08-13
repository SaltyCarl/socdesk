import type { IndicatorType } from './types'
import { classifyIndicator } from './classify'

/**
 * Recent-indicator store — the palette's "recent indicators" group.
 * Persisted to localStorage, newest-first, de-duplicated, capped.
 *
 * Empty-state contract:
 *   • key MISSING  → first run → curated SAMPLE (demonstrates the group +
 *                    the per-type badges without writing junk to storage).
 *   • key PRESENT but []  → the user genuinely cleared it → show nothing.
 */

export interface RecentIndicator {
  value: string
  type: IndicatorType
  at: number
}

const KEY = 'socdesk-recent-indicators'
const MAX = 8

/** Curated first-run examples (one of each type). Never written to disk. */
const SAMPLE: RecentIndicator[] = [
  { value: '185.220.101.4', type: 'ip', at: 7 },
  { value: 'CVE-2024-3400', type: 'cve', at: 6 },
  { value: 'coactive-mail.com', type: 'domain', at: 5 },
  { value: '44d88612fea8a8f36de82e1278abb02f', type: 'hash', at: 4 },
  { value: 'https://verify-account-login.top/auth', type: 'url', at: 3 },
]

export function getRecents(): RecentIndicator[] {
  try {
    const raw = localStorage.getItem(KEY)
    if (raw == null) return SAMPLE
    const parsed = JSON.parse(raw) as unknown
    if (!Array.isArray(parsed)) return []
    return parsed
      .filter(
        (r): r is RecentIndicator =>
          !!r && typeof r.value === 'string' && typeof r.type === 'string',
      )
      .slice(0, MAX)
  } catch {
    return SAMPLE
  }
}

export function pushRecent(value: string, type: IndicatorType = classifyIndicator(value)): void {
  const v = value.trim()
  if (!v) return
  try {
    const existing = getStored()
    const next: RecentIndicator[] = [
      { value: v, type, at: Date.now() },
      ...existing.filter((r) => r.value.toLowerCase() !== v.toLowerCase()),
    ].slice(0, MAX)
    localStorage.setItem(KEY, JSON.stringify(next))
  } catch {
    /* storage blocked — recents are best-effort */
  }
}

export function clearRecents(): void {
  try {
    // Empty array (not removeItem) so the SAMPLE fallback does NOT return.
    localStorage.setItem(KEY, '[]')
  } catch {
    /* no-op */
  }
}

/** Stored rows only (no SAMPLE fallback) — the write path's basis. */
function getStored(): RecentIndicator[] {
  try {
    const raw = localStorage.getItem(KEY)
    if (raw == null) return []
    const parsed = JSON.parse(raw) as unknown
    return Array.isArray(parsed) ? (parsed as RecentIndicator[]) : []
  } catch {
    return []
  }
}
