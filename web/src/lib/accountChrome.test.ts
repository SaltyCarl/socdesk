import { describe, expect, it } from 'vitest'
import { accountView, shouldProbeSession } from './accountChrome'

describe('shouldProbeSession — network restraint (no probe when unseen)', () => {
  it('fires no probe for a browser that never engaged reporting', () => {
    expect(shouldProbeSession(false)).toBe(false)
  })
  it('probes for a returning contributor', () => {
    expect(shouldProbeSession(true)).toBe(true)
  })
})

describe('accountView — Part A truth table', () => {
  it('unseen renders nothing, at any status', () => {
    expect(accountView(false, 'loading')).toBe('none')
    expect(accountView(false, 'in')).toBe('none')
    expect(accountView(false, 'out')).toBe('none')
  })
  it('seen + loading renders nothing (brief, no loading chrome)', () => {
    expect(accountView(true, 'loading')).toBe('none')
  })
  it('seen + out renders the quiet Sign-in link', () => {
    expect(accountView(true, 'out')).toBe('signin')
  })
  it('seen + in renders the account chip', () => {
    expect(accountView(true, 'in')).toBe('chip')
  })
})
