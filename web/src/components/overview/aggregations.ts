// aggregations.ts — per-lane selectors for the daily summary.
//
// The feed's 0–100 score is category-capped (a KEV CVE maxes ~85, a ransomware
// leak-site post ~30, an APT report ~8), so a SINGLE score-sorted "top" list is
// always all-CVE — a ranking artifact, not a real picture. Each panel therefore
// ranks its OWN lane from the raw items, never one global queue.
//
// Pure functions, no React, no I/O — trivially testable and reused by both the
// stat strip and its matching panel so their numbers can never disagree.

import type { Cve, FeedItem } from '../views/types'

/* ---------------- ransomware leak-site activity ---------------- */

export interface RansomGroup {
  name: string
  claims: number
}
export interface RansomSummary {
  /** Total victim claims in the window (attributed + unattributed posts). */
  totalClaims: number
  /** Distinct attributed leak-site groups. */
  groupCount: number
  /** Groups ranked by victim-claim count, highest first. */
  groups: RansomGroup[]
}

/**
 * ransomware.live posts arrive PRE-AGGREGATED — one item is "clop posted 5
 * victim claims", with the count in `why` ("5 claims in window") or the title
 * ("posted N victim claims"); a singular "a new victim claim" is 1. Counting
 * ITEMS would badly undercount, so we parse the real claim tally per post.
 *
 * Exported so the actor-profile selectors (views/profiles.ts) sum a single
 * group's claims with the EXACT same parser the board uses — the two surfaces
 * can never disagree on a group's tally.
 */
export function claimCount(it: FeedItem): number {
  const why = (it.why ?? []).join(' ')
  let m = why.match(/(\d+)\s+claims?/i)
  if (m) return Number(m[1])
  m = (it.title ?? '').match(/posted\s+(\d+)\s+victim/i)
  if (m) return Number(m[1])
  return 1
}

/** Aggregate ransomware.live leak-site posts into per-group victim-claim totals. */
export function aggregateRansomware(items: FeedItem[]): RansomSummary {
  const map = new Map<string, number>()
  let totalClaims = 0
  for (const it of items) {
    if (it.source !== 'ransomwarelive') continue
    const c = claimCount(it)
    totalClaims += c
    const name = it.entities?.actors?.[0]
    if (!name) continue // unattributed post: counts toward total, not a group
    map.set(name, (map.get(name) ?? 0) + c)
  }
  const groups = [...map.entries()]
    .map(([name, claims]) => ({ name, claims }))
    .sort((a, b) => b.claims - a.claims || a.name.localeCompare(b.name))
  return { totalClaims, groupCount: groups.length, groups }
}

/* ---------------- named-actor reporting (APT + campaign) ---------------- */

export interface ActorReport {
  id: string
  actors: string[]
  category: string
  /** Headline with the "[Outlet]" prefix stripped off. */
  title: string
  /** The reporting outlet parsed from the "[Outlet]" prefix, else the source. */
  outlet: string
  url?: string
  published_at?: string
}

const OUTLET_RE = /^\s*\[([^\]]+)\]\s*/

/**
 * APT + campaign items that actually NAME a threat actor (Sandworm, Kimsuky,
 * Midnight Blizzard…), newest first. Most campaign items carry no actor, so
 * this lane is honestly small — the panel degrades to a "quiet window" line
 * rather than padding it with unattributed reports.
 */
export function namedActorReports(items: FeedItem[], limit = 6): ActorReport[] {
  const rows: ActorReport[] = []
  for (const it of items) {
    if (it.category !== 'apt' && it.category !== 'campaign') continue
    const actors = it.entities?.actors ?? []
    if (!actors.length) continue
    const m = (it.title ?? '').match(OUTLET_RE)
    rows.push({
      id: it.id,
      actors,
      category: it.category,
      title: (it.title ?? '').replace(OUTLET_RE, ''),
      outlet: m ? m[1] : it.source,
      url: it.url,
      published_at: it.published_at,
    })
  }
  rows.sort((a, b) =>
    String(b.published_at ?? '').localeCompare(String(a.published_at ?? '')),
  )
  return rows.slice(0, limit)
}

/* ---------------- patch priority (the one CVE lane) ---------------- */

/** Exploitation-risk key: KEV membership dominates, EPSS breaks ties — the same
 *  ordering philosophy as the Vulnerabilities desk (riskKey). */
const riskKey = (c: Cve): number => (c.kev ? 2 : 0) + (c.epss ?? 0)

/**
 * CVEs worth patching first: KEV-listed OR EPSS ≥ 50%, ranked by exploitation
 * risk. (A public-PoC signal was specced but the catalog carries no PoC field,
 * so it is omitted rather than faked.)
 */
export function patchPriority(cves: Cve[], limit = 7): Cve[] {
  return cves
    .filter((c) => c.kev === true || (c.epss ?? 0) >= 0.5)
    .sort((a, b) => riskKey(b) - riskKey(a) || (b.cvss ?? 0) - (a.cvss ?? 0))
    .slice(0, limit)
}
