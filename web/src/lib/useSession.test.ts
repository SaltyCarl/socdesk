import { describe, expect, it } from 'vitest'
import { sessionStateFrom, type SessionState } from './useSession'

describe('sessionStateFrom — /api/report/mine probe → session state', () => {
  it('200 with a login is signed in, carrying the handle', () => {
    expect(sessionStateFrom(200, { login: 'octocat' })).toEqual<SessionState>({
      status: 'in',
      login: 'octocat',
    })
  })
  it('200 with no login is still signed in (login is optional)', () => {
    expect(sessionStateFrom(200, {})).toEqual<SessionState>({ status: 'in', login: undefined })
  })
  it('401 is signed out', () => {
    expect(sessionStateFrom(401, null)).toEqual<SessionState>({ status: 'out' })
  })
  it('a 5xx / unexpected status is signed out — never optimistically in', () => {
    expect(sessionStateFrom(503, null).status).toBe('out')
  })
})
