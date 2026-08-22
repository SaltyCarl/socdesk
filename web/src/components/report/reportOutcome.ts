// reportOutcome — the pure heart of the ReportDialog state machine. Maps the
// /api/report response (HTTP status + parsed JSON body, or null on a
// network/parse failure) to a terminal dialog state. Mirrors the server
// contract in functions/api/report.js exactly:
//   200 {deduped:true} → deduped ; 200 → queued
//   401 → expired ; 403 → banned ; 429 → capped
//   400 {error:'turnstile'} → turnstile ; 400 {error:<field>} → invalid(field)
//   anything else / null → error (retryable, draft intact)

export type ReportOutcome =
  | { kind: 'queued' }
  | { kind: 'deduped' }
  | { kind: 'expired' }
  | { kind: 'turnstile' }
  | { kind: 'invalid'; field?: string }
  | { kind: 'banned' }
  | { kind: 'capped' }
  | { kind: 'error' }

export function reportOutcome(
  status: number,
  body: { deduped?: boolean; error?: string } | null,
): ReportOutcome {
  if (status === 200) return body?.deduped ? { kind: 'deduped' } : { kind: 'queued' }
  if (status === 401) return { kind: 'expired' }
  if (status === 403) return { kind: 'banned' }
  if (status === 429) return { kind: 'capped' }
  if (status === 400) {
    if (body?.error === 'turnstile') return { kind: 'turnstile' }
    return { kind: 'invalid', field: body?.error }
  }
  return { kind: 'error' }
}
