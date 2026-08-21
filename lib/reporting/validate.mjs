import { validate } from '../enrich.mjs'

// AbuseIPDB-aligned controlled vocab (eases a future upstream push).
export const CATEGORIES = [
  'brute-force', 'ssh', 'port-scan', 'web-app-attack', 'phishing',
  'malware-c2', 'scanner', 'spam', 'exploited-host', 'other',
]
export const EVIDENCE_MAX = 2000
export const COMMENT_MAX = 1000
const TYPES = ['ipv4', 'ipv6', 'domain', 'url', 'md5', 'sha1', 'sha256']

/** Validate + normalize a report submission. IOC type/value (+ private-IP
 *  rejection) reuse enrich.mjs's validate; category is controlled; evidence is
 *  required. Never trusts client-sent normalization. */
export function validateReport(body) {
  const b = body ?? {}
  if (!TYPES.includes(b.ioc_type)) return { ok: false, error: 'ioc_type', reason: 'unsupported type' }
  const v = validate(b.ioc_type, String(b.ioc_value ?? ''))
  if (!v.ok) return { ok: false, error: 'ioc_value', reason: v.reason }
  if (!CATEGORIES.includes(b.category)) return { ok: false, error: 'category', reason: 'unknown category' }
  const evidence = String(b.evidence ?? '').trim()
  if (!evidence) return { ok: false, error: 'evidence', reason: 'evidence is required' }
  if (evidence.length > EVIDENCE_MAX) return { ok: false, error: 'evidence', reason: 'evidence too long' }
  const comment = String(b.comment ?? '').trim().slice(0, COMMENT_MAX) || null
  return { ok: true, clean: { ioc_type: b.ioc_type, ioc_value: v.value, category: b.category, evidence, comment } }
}
