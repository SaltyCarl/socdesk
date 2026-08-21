export * from '../../lib/reporting/session.mjs'
import { verifyPayload, readCookie, SESSION_COOKIE } from '../../lib/reporting/session.mjs'

/** Resolve the signed-in user from the session cookie, or null. */
export async function requireSession(request, env) {
  const raw = readCookie(request, SESSION_COOKIE)
  if (!raw) return null
  const p = await verifyPayload(raw, env.SESSION_SECRET, Math.floor(Date.now() / 1000))
  return p && typeof p.github_id === 'number' ? { github_id: p.github_id, login: p.login } : null
}
