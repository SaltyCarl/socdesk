// lib/reporting/admin.mjs
// Pure owner-identity check + moderation-action vocabulary + report-id shape
// guard for the /admin console. Kept out of the Functions so they're
// node-testable (mirrors policy.mjs's overDailyCap).

/** True only when `github_id` is a number and matches OWNER_GITHUB_ID
 *  exactly. An unset, blank, whitespace-only, or non-numeric OWNER_GITHUB_ID
 *  always resolves false — the gate fails closed, never open-by-default.
 *  `ownerGithubIdRaw` is trimmed and shape-checked against /^\d+$/ BEFORE
 *  Number() so a whitespace-only value (Number('   ') === 0) can never
 *  coerce into a false match against a github_id of 0. Login/handle is
 *  never part of this check (see the 2026-08-21 security ruling). */
export function isOwner(github_id, ownerGithubIdRaw) {
  if (typeof github_id !== 'number') return false
  const trimmed = typeof ownerGithubIdRaw === 'string' ? ownerGithubIdRaw.trim() : ''
  if (!/^\d+$/.test(trimmed)) return false
  return github_id === Number(trimmed)
}

/** action -> the status write it produces, or null for an unrecognized
 *  action. The only two transitions this phase allows are queued->approved
 *  and queued->rejected (enforced again at the SQL layer — see
 *  updateReportStatus's `WHERE status = 'queued'` guard). */
export function statusForAction(action) {
  if (action === 'approve') return 'approved'
  if (action === 'reject') return 'rejected'
  return null
}

const REPORT_ID_SHAPE = /^[0-9a-f-]{36}$/i

/** Shape-only guard on a report id before it reaches a D1 statement.
 *  insertReport always writes crypto.randomUUID() (functions/api/report.js),
 *  so any id that doesn't look like one is rejected before the query runs —
 *  belt-and-suspenders alongside the parameterized bind (the real injection
 *  defense), not a replacement for it. */
export function isValidReportId(id) {
  return typeof id === 'string' && REPORT_ID_SHAPE.test(id)
}
