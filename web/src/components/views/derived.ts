import type { Profile } from './types'

/**
 * derived.ts — DERIVED analytics over the ATT&CK catalogs (actors.json /
 * malware.json), computed client-side from payloads already served.
 *
 * Doctrine framing: every number here is ARITHMETIC over attributed ATT&CK
 * data — a shared-technique count, a snapshot prevalence, a "listed in N
 * profiles" tally — and the render layer labels each as computed, never as an
 * asserted relationship or a SOCDesk verdict. Pure functions, no I/O, memoized
 * by the caller (the route) on the payload references.
 */

/** One shared-technique peer row: `shared` techniques in common, out of the
 *  peer's `total`. Ranked by JACCARD (shared / union): raw shared-count is
 *  size-dominated (mega-actors crowd every list), and the overlap
 *  coefficient (shared/min) over-rewards TINY near-subset actors — live
 *  dogfood showed 5-technique actors outranking APT28 on APT29's panel.
 *  Jaccard penalizes both extremes; the row still displays the plain
 *  shared count. */
export interface OverlapRow {
  name: string
  slug: string
  shared: number
  total: number
}

const MIN_SHARED = 3
const TOP_PEERS = 5

/** Top peers of `self` by ATT&CK technique overlap. Excludes self by
 *  attack_id (slug comparison fails on an alias-reached page). Suppressed
 *  (empty) when self has < 5 techniques or no peer shares ≥ MIN_SHARED —
 *  the caller renders no panel at all (honest absence, not empty-state
 *  prose). */
export function techniqueOverlap(
  self: { attack_id?: string; name: string; techniques: string[] },
  actors: Profile[],
): OverlapRow[] {
  if (self.techniques.length < 5) return []
  const mine = new Set(self.techniques)
  const rows: (OverlapRow & { coeff: number })[] = []
  for (const p of actors) {
    if (!p?.name || !(p.techniques ?? []).length) continue
    if (p.attack_id && self.attack_id && p.attack_id === self.attack_id) continue
    if (p.name.toLowerCase() === self.name.toLowerCase()) continue
    let shared = 0
    for (const t of p.techniques!) if (mine.has(t)) shared++
    if (shared < MIN_SHARED) continue
    const coeff = shared / (mine.size + p.techniques!.length - shared)
    rows.push({ name: p.name, slug: p.name.toLowerCase(), shared, total: p.techniques!.length, coeff })
  }
  return rows
    .sort((a, b) => b.coeff - a.coeff || b.shared - a.shared || a.name.localeCompare(b.name))
    .slice(0, TOP_PEERS)
    .map(({ name, slug, shared, total }) => ({ name, slug, shared, total }))
}

/** Snapshot prevalence: technique id → how many tracked ACTORS list it.
 *  One pass over actors.json; malware profiles deliberately excluded so
 *  "distinctive" keeps a single, stated denominator (tracked groups). */
export function techniquePrevalence(actors: Profile[]): Map<string, number> {
  const m = new Map<string, number>()
  for (const p of actors) {
    for (const t of p?.techniques ?? []) m.set(t, (m.get(t) ?? 0) + 1)
  }
  return m
}

const DISTINCTIVE_MAX_PREVALENCE = 3

/** Partition a technique list into distinctive (≤3 tracked groups use it in
 *  this snapshot) vs common. distinctive is EMPTY for ~42% of actors — the
 *  render keeps the plain flat wall in that case rather than leading with an
 *  empty header and collapsing everything. */
export function distinctiveSplit(
  techniques: string[],
  prevalence: Map<string, number>,
): { distinctive: string[]; common: string[] } {
  const distinctive: string[] = []
  const common: string[] = []
  for (const t of techniques) {
    // A technique absent from the prevalence map (malware-only, once D2
    // ships malware technique lists) has no ACTOR using it — not "rare".
    const p = prevalence.get(t) ?? 0
    if (p >= 1 && p <= DISTINCTIVE_MAX_PREVALENCE) distinctive.push(t)
    else common.push(t)
  }
  return { distinctive, common }
}

/** The reverse index for a malware/tool name: every tracked group whose
 *  ATT&CK fingerprint lists it (exact ingest-symmetric names; compared
 *  case-insensitively as cheap tolerance). ATT&CK-derived ONLY — never the
 *  feed co-occurrence union, whose panel explicitly disclaims "uses". */
export function usedByGroups(
  malwareName: string,
  actors: Profile[],
): { name: string; slug: string }[] {
  const needle = malwareName.toLowerCase()
  const out: { name: string; slug: string }[] = []
  for (const p of actors) {
    if (!p?.name) continue
    if ((p.software ?? []).some((s) => s.toLowerCase() === needle)) {
      out.push({ name: p.name, slug: p.name.toLowerCase() })
    }
  }
  return out.sort((a, b) => a.name.localeCompare(b.name))
}

/** Directory-scale reverse-index counts: lowercased software name → number of
 *  tracked groups listing it. One pass; joined onto malware index entries. */
export function usedByCounts(actors: Profile[]): Map<string, number> {
  const m = new Map<string, number>()
  for (const p of actors) {
    for (const s of p?.software ?? []) {
      const k = s.toLowerCase()
      m.set(k, (m.get(k) ?? 0) + 1)
    }
  }
  return m
}
