import { describe, expect, it } from 'vitest'
import { dialogView } from './dialogView'

describe('dialogView — base screen from session status', () => {
  it('loading → the brief loading tick', () => {
    expect(dialogView('loading')).toBe('loading')
  })
  it('out → the sign-in gate', () => {
    expect(dialogView('out')).toBe('gate')
  })
  it('in → the fill form', () => {
    expect(dialogView('in')).toBe('fill')
  })
})
