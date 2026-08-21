import { requireSession } from '../../_lib/session.mjs'
import { listMyReports } from '../../../lib/reporting/db.mjs'

export async function onRequestGet({ request, env }) {
  const user = await requireSession(request, env)
  if (!user) return new Response(JSON.stringify({ error: 'auth' }), { status: 401, headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } })
  const reports = await listMyReports(env.DB, user.github_id)
  return new Response(JSON.stringify({ reports }), { status: 200, headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } })
}
