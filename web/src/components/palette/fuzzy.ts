/**
 * Tiny fzf-style subsequence matcher — reimplemented (no dependency) so
 * the palette filter is CSP-clean and predictable. Returns a score
 * (higher = better) plus the matched character spans for highlighting.
 * `null` means "no match".
 *
 * Scoring rewards, in order of weight: a match at the very start, a match
 * on a word boundary, and runs of consecutive characters — the shape of a
 * good command-palette hit. Earlier and tighter matches win.
 */

export interface FuzzyResult {
  score: number
  /** Half-open [start, end) spans in the ORIGINAL text, merged + ordered. */
  ranges: Array<[number, number]>
}

const SEPARATOR = /[\s\-_./:@]/

export function fuzzyMatch(query: string, text: string): FuzzyResult | null {
  const q = query.toLowerCase()
  const t = text.toLowerCase()
  if (!q) return { score: 0, ranges: [] }

  // Greedy leftmost subsequence.
  const matched: number[] = []
  let qi = 0
  for (let ti = 0; ti < t.length && qi < q.length; ti++) {
    if (t[ti] === q[qi]) {
      matched.push(ti)
      qi += 1
    }
  }
  if (qi < q.length) return null

  let score = 0
  let prev = -2
  for (const idx of matched) {
    if (idx === prev + 1) score += 8 // consecutive run
    if (idx === 0) score += 14 // hard start
    else if (SEPARATOR.test(text[idx - 1])) score += 7 // word boundary
    score -= idx * 0.1 // earlier is better
    prev = idx
  }
  // Brevity bonus — a short haystack that the query nearly fills.
  score += Math.max(0, 8 - (t.length - q.length) * 0.2)

  // Merge adjacent matched indices into contiguous spans.
  const ranges: Array<[number, number]> = []
  for (const idx of matched) {
    const last = ranges[ranges.length - 1]
    if (last && idx === last[1]) last[1] = idx + 1
    else ranges.push([idx, idx + 1])
  }

  return { score, ranges }
}
