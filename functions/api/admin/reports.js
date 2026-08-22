import { requireSession } from '../../_lib/session.mjs'
import { isOwner } from '../../../lib/reporting/admin.mjs'
import { listQueuedReports } from '../../../lib/reporting/db.mjs'

const json = (body, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } })

export async function onRequestGet({ request, env }) {
  const user = await requireSession(request, env)
  if (!user) return json({ error: 'auth' }, 401)
  if (!isOwner(user.github_id, env.OWNER_GITHUB_ID)) return json({ error: 'forbidden' }, 403)
  const reports = await listQueuedReports(env.DB)
  return json({ reports }, 200)
}
