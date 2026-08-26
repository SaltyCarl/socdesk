import { signPayload, oauthNonceCookie } from '../../../_lib/session.mjs'

export async function onRequestGet({ request, env }) {
  const url = new URL(request.url)
  const ret = url.searchParams.get('return') || '/'
  // Signed state carries the return path + a short expiry AND a per-flow nonce.
  // The same nonce is set as a browser cookie; the callback rejects unless the
  // two match — so a signed state can't be replayed from a different browser
  // (login-CSRF). Signing alone is not browser-binding.
  const nonce = crypto.randomUUID()
  const state = await signPayload(
    { return: ret, nonce, exp: Math.floor(Date.now() / 1000) + 600 }, env.SESSION_SECRET)
  const authorize = new URL('https://github.com/login/oauth/authorize')
  authorize.searchParams.set('client_id', env.GITHUB_CLIENT_ID)
  authorize.searchParams.set('redirect_uri', `${url.origin}/api/auth/github/callback`)
  authorize.searchParams.set('scope', '') // default scope: public profile only
  authorize.searchParams.set('state', state)
  authorize.searchParams.set('allow_signup', 'true')
  // Response.redirect() can't carry a Set-Cookie, so build the 302 by hand.
  return new Response(null, {
    status: 302,
    headers: { location: authorize.toString(), 'set-cookie': oauthNonceCookie(nonce) },
  })
}
