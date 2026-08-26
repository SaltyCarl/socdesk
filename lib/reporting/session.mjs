// Pure HMAC-SHA256 sign/verify over base64url(JSON) — used for both the session
// cookie and the OAuth `state`. Web Crypto (crypto.subtle) exists in the Pages
// Functions runtime AND in node 20+, so this is unit-testable.
const enc = new TextEncoder()
export const SESSION_COOKIE = 'sd_session'

function b64urlEncode(bytes) {
  let bin = ''
  for (const b of bytes) bin += String.fromCharCode(b)
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}
function b64urlDecode(s) {
  const pad = s.length % 4 ? '='.repeat(4 - (s.length % 4)) : ''
  const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/') + pad)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}
async function hmacKey(secret) {
  // A falsy secret would encode the literal string "undefined" as the key,
  // making every signature forgeable. Fail CLOSED instead: verifyPayload's
  // try/catch turns this into null (no session), and signPayload propagates it
  // (a 500 — never issue a session/state signed with an empty key).
  if (!secret) throw new Error('SESSION_SECRET is not set')
  return crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify'])
}

export async function signPayload(payload, secret) {
  const body = b64urlEncode(enc.encode(JSON.stringify(payload)))
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', await hmacKey(secret), enc.encode(body)))
  return `${body}.${b64urlEncode(sig)}`
}

export async function verifyPayload(token, secret, nowSec) {
  if (typeof token !== 'string') return null
  const parts = token.split('.')
  if (parts.length !== 2 || !parts[0] || !parts[1]) return null
  let ok
  try {
    ok = await crypto.subtle.verify('HMAC', await hmacKey(secret), b64urlDecode(parts[1]), enc.encode(parts[0]))
  } catch { return null }
  if (!ok) return null
  let payload
  try { payload = JSON.parse(new TextDecoder().decode(b64urlDecode(parts[0]))) } catch { return null }
  if (typeof payload?.exp === 'number' && nowSec >= payload.exp) return null
  return payload
}

/** Cookie header helpers. HttpOnly + Secure + Lax; ~30d. */
export function sessionCookie(value, maxAgeSec) {
  return `${SESSION_COOKIE}=${value}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${maxAgeSec}`
}
export function clearCookie() {
  return `${SESSION_COOKIE}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`
}

/** Short-lived nonce cookie that binds an OAuth `state` to the browser that
 *  STARTED the flow — the callback rejects unless the state's nonce matches
 *  this cookie (defeats login-CSRF / state replay from another browser).
 *  SameSite=Lax so it rides the top-level GET redirect back from the provider;
 *  scoped to /api/auth so it never travels with normal page loads. */
export const OAUTH_NONCE_COOKIE = 'sd_oauth_nonce'
export function oauthNonceCookie(value) {
  return `${OAUTH_NONCE_COOKIE}=${value}; HttpOnly; Secure; SameSite=Lax; Path=/api/auth; Max-Age=600`
}
export function clearOauthNonceCookie() {
  return `${OAUTH_NONCE_COOKIE}=; HttpOnly; Secure; SameSite=Lax; Path=/api/auth; Max-Age=0`
}
export function readCookie(request, name) {
  const raw = request.headers.get('Cookie') || ''
  const m = raw.match(new RegExp(`(?:^|; )${name}=([^;]+)`))
  return m ? m[1] : null
}
