import { describe, expect, it } from 'vitest'
import { signPayload, verifyPayload } from '../session.mjs'

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
})
