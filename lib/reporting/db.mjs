// D1 data-access module for IOC reporting. Every query goes through the
// D1 prepared-statement API with positional (?N) bindings — never string-
// build SQL with user-supplied values.

export async function upsertAccount(DB, github_id, login, nowIso) {
  await DB.prepare(
    `INSERT INTO accounts (github_id, login, created_at, last_seen)
     VALUES (?1, ?2, ?3, ?3)
     ON CONFLICT(github_id) DO UPDATE SET login = ?2, last_seen = ?3`,
  ).bind(github_id, login, nowIso).run()
}

export async function getAccount(DB, github_id) {
  return DB.prepare(`SELECT banned FROM accounts WHERE github_id = ?1`).bind(github_id).first()
}

export async function countReportsSince(DB, github_id, sinceIso) {
  const row = await DB.prepare(
    `SELECT COUNT(*) AS n FROM reports WHERE github_id = ?1 AND created_at >= ?2`,
  ).bind(github_id, sinceIso).first()
  return Number(row?.n ?? 0)
}

export async function findQueuedDuplicate(DB, github_id, ioc_type, ioc_value) {
  return DB.prepare(
    `SELECT id FROM reports WHERE github_id = ?1 AND ioc_type = ?2 AND ioc_value = ?3 AND status = 'queued' LIMIT 1`,
  ).bind(github_id, ioc_type, ioc_value).first()
}

export async function insertReport(DB, r) {
  await DB.prepare(
    `INSERT INTO reports (id, github_id, ioc_type, ioc_value, category, evidence, comment, status, created_at)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'queued', ?8)`,
  ).bind(r.id, r.github_id, r.ioc_type, r.ioc_value, r.category, r.evidence, r.comment, r.created_at).run()
}

export async function listMyReports(DB, github_id) {
  const { results } = await DB.prepare(
    `SELECT id, ioc_type, ioc_value, category, status, created_at
     FROM reports WHERE github_id = ?1 ORDER BY created_at DESC LIMIT 200`,
  ).bind(github_id).all()
  return results ?? []
}

/** The moderation queue, oldest-first (FIFO — nothing should go stale)
 *  unlike listMyReports' newest-first (an author wants their latest report
 *  on top). Joins accounts for the reporter's handle; LEFT JOIN so a report
 *  never disappears from the queue if its account row is ever missing. */
export async function listQueuedReports(DB, limit = 200) {
  const { results } = await DB.prepare(
    `SELECT r.id, r.github_id, a.login, r.ioc_type, r.ioc_value, r.category,
            r.evidence, r.comment, r.status, r.created_at
     FROM reports r LEFT JOIN accounts a ON a.github_id = r.github_id
     WHERE r.status = 'queued' ORDER BY r.created_at ASC LIMIT ?1`,
  ).bind(limit).all()
  return results ?? []
}

/** Transition a report's status. The `AND status = 'queued'` guard makes
 *  this race-safe: a double-click, two open admin tabs, or a retry after a
 *  dropped response can only ever produce one write — the second call
 *  returns `changes: 0` rather than clobbering an already-decided report.
 *  Returns true iff a row was actually changed. */
export async function updateReportStatus(DB, id, status) {
  const res = await DB.prepare(
    `UPDATE reports SET status = ?1 WHERE id = ?2 AND status = 'queued'`,
  ).bind(status, id).run()
  return (res.meta?.changes ?? 0) > 0
}
