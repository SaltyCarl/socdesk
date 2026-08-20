// findingLead.ts — the pure lead-figure split behind the evidence-row highlight.
// Kept framework-free (no React) so it is unit-testable in the node test env.

/** Split a finding into its lead figure — a leading percentage / ratio / number
 *  ("0%", "0/91"), else the first clause up to a separator ("opportunistic
 *  scanner") — and the remainder, so the highlight lands on the number that
 *  matters. Returns [lead, rest]; `rest` includes its leading space/separator. */
export function splitLead(finding: string): [string, string] {
  const num = finding.match(/^\s*[\d.,]+%?(?:\s*\/\s*[\d.,]+)?/)
  if (num && /\d/.test(num[0])) return [num[0].trim(), finding.slice(num[0].length)]
  const sep = finding.search(/\s[·—]\s|,\s/)
  if (sep > 0) return [finding.slice(0, sep), finding.slice(sep)]
  return [finding, '']
}
