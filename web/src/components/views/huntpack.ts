import type { HuntRule, TechniqueTacticsPayload } from './types'

/**
 * huntpack.ts — the pure join between a profile's ATT&CK technique fingerprint
 * and the hunt_packs.json rule corpus. No React, no I/O — unit-tested in a
 * plain node env.
 *
 * Join rule (spec §H4): parent-normalized — a rule matches a profile
 * technique when their parent ids (the `Txxxx` before any `.yyy`) intersect;
 * an EXACT id match ranks above a family-level one. Caps: ≤3 rules per
 * profile technique (kind priority socdesk > sentinel > sigma, then
 * exact-over-family, then source.modified desc, then id — deterministic),
 * 50 rows per panel with the remainder counted for a collapsed disclosure.
 * A rule renders ONCE, placed under the kill-chain-EARLIEST tactic of its
 * matched techniques (bundle order from the tactics catalog; absent catalog
 * → one flat section).
 */

export interface HuntRow {
  rule: HuntRule
  /** exact-id match vs family-level (parent) match — rendered as-is never,
   *  but drives ranking and tests. */
  exact: boolean
  /** the profile technique(s) this rule matched. */
  matched: string[]
}

export interface HuntSection {
  slug: string
  name: string
  rows: HuntRow[]
}

export interface HuntPack {
  sections: HuntSection[]
  /** profile techniques with no matching rule, pre-compromise tactics
   *  EXCLUDED (reconnaissance/resource-development are not host-huntable —
   *  their floor links would be dead weight; stated in the panel note). */
  uncovered: string[]
  /** count of pre-compromise techniques omitted from `uncovered`. */
  preCompromiseOmitted: number
  totalMatched: number
  /** rows beyond the 50-row panel cap (collapsed disclosure count). */
  overflow: number
}

const PER_TECHNIQUE_CAP = 3
const PANEL_CAP = 50
const KIND_PRIORITY: Record<string, number> = { socdesk: 3, sentinel: 2, sigma: 1 }
const PRE_COMPROMISE = new Set(['reconnaissance', 'resource-development'])

const parent = (t: string): string => t.split('.')[0]

function ruleSort(a: { rule: HuntRule; exact: boolean }, b: { rule: HuntRule; exact: boolean }): number {
  return (
    (KIND_PRIORITY[b.rule.source.kind] ?? 0) - (KIND_PRIORITY[a.rule.source.kind] ?? 0) ||
    Number(b.exact) - Number(a.exact) ||
    (b.rule.source.modified ?? '').localeCompare(a.rule.source.modified ?? '') ||
    a.rule.id.localeCompare(b.rule.id)
  )
}

export function buildHuntPack(
  techniques: string[],
  rules: HuntRule[],
  catalog?: TechniqueTacticsPayload,
): HuntPack {
  // rule index by parent id
  const byParent = new Map<string, HuntRule[]>()
  for (const r of rules) {
    for (const t of r.techniques) {
      const p = parent(t)
      const arr = byParent.get(p) ?? []
      if (!arr.includes(r)) arr.push(r)
      byParent.set(p, arr)
    }
  }

  const tacticOrder = new Map<string, number>()
  const tacticName = new Map<string, string>()
  for (const [i, o] of (catalog?.order ?? []).entries()) {
    tacticOrder.set(o.slug, i)
    tacticName.set(o.slug, o.name)
  }
  const tacticsOf = (t: string): string[] => catalog?.tactics[t] ?? catalog?.tactics[parent(t)] ?? []
  const earliestTactic = (ids: string[]): string => {
    let best = 'other'
    let bestIdx = Number.POSITIVE_INFINITY
    for (const id of ids) {
      for (const slug of tacticsOf(id)) {
        const idx = tacticOrder.get(slug)
        if (idx !== undefined && idx < bestIdx) {
          bestIdx = idx
          best = slug
        }
      }
    }
    return best
  }

  // per-technique candidate selection, then global dedupe
  const placed = new Map<string, HuntRow>() // rule id -> row
  const uncovered: string[] = []
  let preCompromiseOmitted = 0
  for (const t of techniques) {
    const candidates = (byParent.get(parent(t)) ?? [])
      .map((r) => ({ rule: r, exact: r.techniques.includes(t) }))
      .sort(ruleSort)
      .slice(0, PER_TECHNIQUE_CAP)
    if (!candidates.length) {
      // pre-compromise techniques are omitted from the floor (not host-huntable)
      const slugs = tacticsOf(t)
      if (slugs.length && slugs.every((s) => PRE_COMPROMISE.has(s))) preCompromiseOmitted++
      else uncovered.push(t)
      continue
    }
    for (const c of candidates) {
      const existing = placed.get(c.rule.id)
      if (existing) {
        if (!existing.matched.includes(t)) existing.matched.push(t)
        existing.exact = existing.exact || c.exact
      } else {
        placed.set(c.rule.id, { rule: c.rule, exact: c.exact, matched: [t] })
      }
    }
  }

  let rows = [...placed.values()]
  const totalMatched = rows.length
  const overflow = Math.max(0, rows.length - PANEL_CAP)
  if (overflow) {
    rows = rows.sort(ruleSort).slice(0, PANEL_CAP)
  }

  // group by earliest tactic, sections in bundle order (other last)
  const bySection = new Map<string, HuntRow[]>()
  for (const row of rows) {
    const slug = earliestTactic(row.matched)
    const arr = bySection.get(slug) ?? []
    arr.push(row)
    bySection.set(slug, arr)
  }
  const slugs = [...bySection.keys()].sort(
    (a, b) => (tacticOrder.get(a) ?? 999) - (tacticOrder.get(b) ?? 999) || a.localeCompare(b),
  )
  const sections = slugs.map((slug) => ({
    slug,
    name: tacticName.get(slug) ?? (slug === 'other' ? 'Other' : slug),
    rows: bySection.get(slug)!.sort(ruleSort),
  }))

  return { sections, uncovered, preCompromiseOmitted, totalMatched, overflow }
}

/** Floor link targets — plain anchors (CSP restricts loaded resources only).
 *  ATT&CK's detection section anchor is `#detection` (live-verified; a
 *  sub-technique id becomes Txxxx/yyy). The SigmaHQ code-search link needs a
 *  GitHub sign-in for anonymous users — the panel labels it. */
export function attackDetectionUrl(t: string): string {
  const [p, sub] = t.split('.')
  return `https://attack.mitre.org/techniques/${p}${sub ? `/${sub}` : ''}/#detection`
}

export function sigmaSearchUrl(t: string): string {
  return `https://github.com/search?q=repo%3ASigmaHQ%2Fsigma+attack.${t.toLowerCase()}&type=code`
}
