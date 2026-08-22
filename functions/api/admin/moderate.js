import { requireSession } from '../../_lib/session.mjs'
import { isOwner, isValidReportId, statusForAction } from '../../../lib/reporting/admin.mjs'
import { updateReportStatus } from '../../../lib/reporting/db.mjs'

const json = (body, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } })

export async function onRequestPost({ request, env }) {
  const user = await requireSession(request, env)
  if (!user) return json({ error: 'auth' }, 401)
  if (!isOwner(user.github_id, env.OWNER_GITHUB_ID)) return json({ error: 'forbidden' }, 403)

  const body = await request.json().catch(() => null)
  const id = body && typeof body.id === 'string' ? body.id : null
  const status = body && statusForAction(body.action)
  if (!id || !status) return json({ error: 'body', reason: 'expected { id, action: "approve"|"reject" }' }, 400)
  if (!isValidReportId(id)) return json({ error: 'body', reason: 'id is not a valid report id' }, 400)

  const changed = await updateReportStatus(env.DB, id, status)
  if (!changed) return json({ error: 'not_found', reason: 'no queued report with that id' }, 404)
  return json({ id, status }, 200)
}
