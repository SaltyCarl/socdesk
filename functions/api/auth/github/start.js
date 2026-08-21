import { signPayload } from '../../../_lib/session.mjs'

export async function onRequestGet({ request, env }) {
  const url = new URL(request.url)
  const ret = url.searchParams.get('return') || '/'
  // Signed state carries the return path + a short expiry (CSRF protection).
  const state = await signPayload({ return: ret, exp: Math.floor(Date.now() / 1000) + 600 }, env.SESSION_SECRET)
  const authorize = new URL('https://github.com/login/oauth/authorize')
  authorize.searchParams.set('client_id', env.GITHUB_CLIENT_ID)
  authorize.searchParams.set('redirect_uri', `${url.origin}/api/auth/github/callback`)
  authorize.searchParams.set('scope', '') // default scope: public profile only
  authorize.searchParams.set('state', state)
  authorize.searchParams.set('allow_signup', 'true')
  return Response.redirect(authorize.toString(), 302)
}
