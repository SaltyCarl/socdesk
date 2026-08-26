import { describe, expect, it } from 'vitest'
import {
  signPayload,
  verifyPayload,
  oauthNonceCookie,
  clearOauthNonceCookie,
  readCookie,
  OAUTH_NONCE_COOKIE,
} from '../session.mjs'

const secret = 'unit-test-secret-please-rotate-0123456789'

describe('signPayload/verifyPayload', () => {
  it('round-trips a valid payload', async () => {
    const t = await signPayload({ github_id: 42, login: 'alice', exp: 9_999_999_999 }, secret)
    expect(await verifyPayload(t, secret, 1000)).toMatchObject({ github_id: 42, login: 'alice' })
  })
  it('rejects a tampered body', async () => {
    const t = await signPayload({ github_id: 42, exp: 9_999_999_999 }, secret)
    const [b, s] = t.split('.')
    const forged = `${b.slice(0, -1)}${b.slice(-1) === 'A' ? 'B' : 'A'}.${s}`
    expect(await verifyPayload(forged, secret, 1000)).toBeNull()
  })
  it('rejects the wrong secret', async () => {
    const t = await signPayload({ github_id: 42, exp: 9_999_999_999 }, secret)
    expect(await verifyPayload(t, 'other-secret', 1000)).toBeNull()
  })
  it('rejects an expired payload', async () => {
    const t = await signPayload({ github_id: 42, exp: 500 }, secret)
    expect(await verifyPayload(t, secret, 1000)).toBeNull()
  })
  it('rejects malformed input', async () => {
    expect(await verifyPayload('', secret, 1000)).toBeNull()
    expect(await verifyPayload('nodot', secret, 1000)).toBeNull()
    expect(await verifyPayload('a.b.c', secret, 1000)).toBeNull()
  })
  it('fails CLOSED when the secret is unset — never signs with an empty key', async () => {
    // An empty secret would HMAC the literal "undefined" (forgeable). signPayload
    // must throw (surfaces as a 500); verifyPayload must return null (no session).
    await expect(signPayload({ github_id: 1, exp: 9_999_999_999 }, undefined)).rejects.toThrow()
    await expect(signPayload({ github_id: 1, exp: 9_999_999_999 }, '')).rejects.toThrow()
    const t = await signPayload({ github_id: 1, exp: 9_999_999_999 }, secret)
    expect(await verifyPayload(t, undefined, 1000)).toBeNull()
    expect(await verifyPayload(t, '', 1000)).toBeNull()
  })
})

describe('oauth nonce cookie helpers', () => {
  it('sets an HttpOnly, Secure, path-scoped nonce cookie', () => {
    const c = oauthNonceCookie('abc-123')
    expect(c).toContain(`${OAUTH_NONCE_COOKIE}=abc-123`)
    expect(c).toContain('HttpOnly')
    expect(c).toContain('Secure')
    expect(c).toContain('SameSite=Lax')
    expect(c).toContain('Path=/api/auth')
    expect(c).toContain('Max-Age=600')
  })
  it('clears the nonce cookie with Max-Age=0', () => {
    const c = clearOauthNonceCookie()
    expect(c).toContain(`${OAUTH_NONCE_COOKIE}=;`)
    expect(c).toContain('Max-Age=0')
  })
  it('reads a named cookie from the request header, or null when absent', () => {
    const req = { headers: { get: () => 'a=1; sd_oauth_nonce=xyz; b=2' } }
    expect(readCookie(req, OAUTH_NONCE_COOKIE)).toBe('xyz')
    const empty = { headers: { get: () => '' } }
    expect(readCookie(empty, OAUTH_NONCE_COOKIE)).toBeNull()
  })
})
