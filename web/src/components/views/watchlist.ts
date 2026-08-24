// watchlist — a per-browser list of vendor/product strings the analyst owns
// ("fortinet", "citrix"). Client-only, no PII, never transmitted: COMPLIANCE.md
// bars a SERVER-side shared watchlist, not a private local one. SSR-safe: every
// storage touch is wrapped (private mode / no DOM throws), mirroring
// lib/contributorSeen.ts. The pure helpers below are unit-tested; only
// load/save touch storage.

import type { Cve } from './types'

const KEY = 'sd_vuln_watchlist'
const MAX_TERMS = 40

/** Normalise a raw term: trimmed, lowercased, inner whitespace collapsed. */
export function normalizeTerm(raw: string): string {
  return raw.trim().toLowerCase().replace(/\s+/g, ' ')
}

/** Add a term (normalised, deduped, capped). Returns a NEW array; the same
 *  array reference back when the term is blank or already present, so a caller
 *  can skip a needless persist. */
export function addTerm(terms: string[], raw: string): string[] {
  const t = normalizeTerm(raw)
  if (!t || terms.includes(t)) return terms
  return [...terms, t].slice(0, MAX_TERMS)
}

/** Remove a term. Returns a NEW array. */
export function removeTerm(terms: string[], term: string): string[] {
  return terms.filter((t) => t !== term)
}

/** True when the CVE's title / products / vendors contain any watchlist term.
 *  Substring match on the same fields the search box covers, minus the CVE id
 *  (a watchlist is about what you OWN, not a CVE number). Empty list → false. */
export function matchesWatchlist(cve: Cve, terms: string[]): boolean {
  if (!terms.length) return false
  const hay = (
    (cve.title ?? '') +
    ' ' +
    (cve.products ?? []).join(' ') +
    ' ' +
    (cve.vendors ?? []).join(' ')
  ).toLowerCase()
  return terms.some((t) => hay.includes(t))
}

/** Load the saved watchlist (normalised, deduped). [] when absent, blocked, or
 *  corrupt — never throws. */
export function loadWatchlist(): string[] {
  try {
    const raw = localStorage.getItem(KEY)
    if (!raw) return []
    const parsed: unknown = JSON.parse(raw)
    if (!Array.isArray(parsed)) return []
    return [...new Set(parsed.map((t) => normalizeTerm(String(t))).filter(Boolean))]
  } catch {
    return []
  }
}

/** Persist the watchlist; silently no-ops when storage is blocked. */
export function saveWatchlist(terms: string[]): void {
  try {
    localStorage.setItem(KEY, JSON.stringify(terms))
  } catch {
    /* storage blocked — the watchlist just won't persist this session */
  }
}
