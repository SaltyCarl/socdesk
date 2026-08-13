// relations.ts — the ranked RELATED list, ported from site/js/related.js.
//
// docs/RELATIONSHIPS.md settles the presentation: a list keyed to the entity
// in focus, NOT a node-link graph. The payload is an evidence-carrying edge
// list; ranking is deterministic — live feed evidence before encyclopedia
// structure, then edge weight, then KEV endpoints, then name.

import type { Evidence, RelEdge, RelNode, RelationsPayload } from './types'

export interface RelatedRow {
  node: RelNode
  edge: RelEdge
}

/** An index over relations.json — built once, queried per focused entity. */
export interface RelationsIndex {
  byName: Map<string, RelNode>
  byId: Map<string, RelNode>
  adj: Map<string, RelEdge[]>
}

export function buildRelationsIndex(rel?: RelationsPayload | null): RelationsIndex {
  const byId = new Map<string, RelNode>()
  const byName = new Map<string, RelNode>()
  const adj = new Map<string, RelEdge[]>()
  if (!rel || !Array.isArray(rel.nodes) || !Array.isArray(rel.edges)) {
    return { byName, byId, adj }
  }
  for (const n of rel.nodes) {
    byId.set(n.id, n)
    byName.set(String(n.name).toLowerCase(), n)
  }
  for (const e of rel.edges) {
    if (!adj.has(e.src)) adj.set(e.src, [])
    if (!adj.has(e.dst)) adj.set(e.dst, [])
    adj.get(e.src)!.push(e)
    adj.get(e.dst)!.push(e)
  }
  return { byName, byId, adj }
}

const isFeedEvidence = (ev: Evidence): boolean =>
  ev[0] !== 'attack' && ev[0] !== 'cve-db'

/** How the edge is attested — the RELATED row's provenance stamp. */
export function provenance(ev: Evidence): string {
  if (ev[0] === 'attack') return 'ATT&CK'
  if (ev[0] === 'cve-db') return 'CVE db'
  return `${ev.length} feed item${ev.length === 1 ? '' : 's'}`
}

/** Neighbours of the focused names, ranked and de-duplicated. */
export function relatedFor(
  index: RelationsIndex,
  names: string[],
  max = 8,
): RelatedRow[] {
  const focus = names
    .map((n) => index.byName.get(String(n).toLowerCase()))
    .filter((n): n is RelNode => Boolean(n))
  if (!focus.length) return []

  const focusIds = new Set(focus.map((n) => n.id))
  const seen = new Set<string>()
  const rows: RelatedRow[] = []

  for (const f of focus) {
    for (const e of index.adj.get(f.id) ?? []) {
      const otherId = e.src === f.id ? e.dst : e.src
      if (focusIds.has(otherId) || seen.has(otherId)) continue
      const other = index.byId.get(otherId)
      if (!other) continue
      seen.add(otherId)
      rows.push({ node: other, edge: e })
    }
  }

  rows.sort(
    (a, b) =>
      Number(isFeedEvidence(b.edge.evidence)) -
        Number(isFeedEvidence(a.edge.evidence)) ||
      b.edge.weight - a.edge.weight ||
      Number(b.node.kev === true) - Number(a.node.kev === true) ||
      a.node.name.localeCompare(b.node.name),
  )
  return rows.slice(0, max)
}

/** Only these types resolve as an in-app pivot; techniques deep-link to
 *  ATT&CK, everything else is context (not a destination). */
export const PIVOTABLE = new Set(['actor', 'malware'])

export const techniqueUrl = (id: string): string =>
  `https://attack.mitre.org/techniques/${encodeURIComponent(id).replace(/\./g, '/')}/`
