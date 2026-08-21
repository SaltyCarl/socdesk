import { requireSession } from '../_lib/session.mjs'
import { validateReport } from '../../lib/reporting/validate.mjs'
import { overDailyCap } from '../../lib/reporting/policy.mjs'
import { getAccount, countReportsSince, findQueuedDuplicate, insertReport } from '../../lib/reporting/db.mjs'

const json = (body, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } })

async function turnstileOk(token, secret, ip) {
  if (!token) return false
  const r = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ secret, response: token, remoteip: ip }),
  }).then((x) => x.json()).catch(() => null)
  return !!r?.success
}

export async function onRequestPost({ request, env }) {
  const user = await requireSession(request, env)
  if (!user) return json({ error: 'auth', reason: 'sign in to report' }, 401)

  const body = await request.json().catch(() => null)
  if (!body) return json({ error: 'body', reason: 'invalid JSON' }, 400)

  const ip = request.headers.get('CF-Connecting-IP') || ''
  if (!(await turnstileOk(body.turnstileToken, env.TURNSTILE_SECRET, ip)))
    return json({ error: 'turnstile', reason: 'challenge failed' }, 400)

  const v = validateReport(body)
  if (!v.ok) return json({ error: v.error, reason: v.reason }, 400)

  const acct = await getAccount(env.DB, user.github_id)
  if (acct?.banned) return json({ error: 'banned', reason: 'account cannot report' }, 403)

  const sinceIso = new Date(Date.now() - 24 * 3600 * 1000).toISOString()
  if (overDailyCap(await countReportsSince(env.DB, user.github_id, sinceIso)))
    return json({ error: 'rate', reason: 'daily report cap reached' }, 429)

  const dup = await findQueuedDuplicate(env.DB, user.github_id, v.clean.ioc_type, v.clean.ioc_value)
  if (dup) return json({ id: dup.id, status: 'queued', deduped: true }, 200)

  const id = crypto.randomUUID()
  await insertReport(env.DB, { id, github_id: user.github_id, ...v.clean, created_at: new Date().toISOString() })
  return json({ id, status: 'queued' }, 200)
}
