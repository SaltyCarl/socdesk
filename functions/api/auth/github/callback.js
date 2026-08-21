import { signPayload, verifyPayload, sessionCookie } from '../../../_lib/session.mjs'
import { upsertAccount } from '../../../../lib/reporting/db.mjs'

const SESSION_TTL = 30 * 24 * 3600 // ~30 days

export async function onRequestGet({ request, env }) {
  const url = new URL(request.url)
  const code = url.searchParams.get('code')
  const state = url.searchParams.get('state')
  const st = state && (await verifyPayload(state, env.SESSION_SECRET, Math.floor(Date.now() / 1000)))
  if (!code || !st) return new Response('bad oauth state', { status: 400 })

  const tok = await fetch('https://github.com/login/oauth/access_token', {
    method: 'POST',
    headers: { accept: 'application/json', 'content-type': 'application/json' },
    body: JSON.stringify({
      client_id: env.GITHUB_CLIENT_ID, client_secret: env.GITHUB_CLIENT_SECRET,
      code, redirect_uri: `${url.origin}/api/auth/github/callback`,
    }),
  }).then((r) => r.json()).catch(() => null)
  if (!tok?.access_token) return new Response('token exchange failed', { status: 502 })

  const gh = await fetch('https://api.github.com/user', {
    headers: { authorization: `Bearer ${tok.access_token}`, 'user-agent': 'SOCDesk', accept: 'application/vnd.github+json' },
  }).then((r) => r.json()).catch(() => null)
  if (!gh?.id || !gh?.login) return new Response('profile fetch failed', { status: 502 })

  const nowIso = new Date().toISOString()
  await upsertAccount(env.DB, gh.id, gh.login, nowIso)
  const session = await signPayload(
    { github_id: gh.id, login: gh.login, exp: Math.floor(Date.now() / 1000) + SESSION_TTL }, env.SESSION_SECRET)

  // Return only to a same-origin path (never an open redirect).
  const dest = st.return && st.return.startsWith('/') && !st.return.startsWith('//') ? st.return : '/'
  return new Response(null, {
    status: 302,
    headers: { location: dest, 'set-cookie': sessionCookie(session, SESSION_TTL) },
  })
}
