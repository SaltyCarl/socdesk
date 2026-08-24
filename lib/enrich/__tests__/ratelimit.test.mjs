import { describe, expect, it } from 'vitest'
import { ipDecision, WINDOW_MS, IP_LIMIT, BLOCK_TTL_MS } from '../ratelimit.mjs'

describe('ipDecision', () => {
  it('allows under the limit and sets no latch', () => {
    const d = ipDecision({ now: 1000, windowStart: 1000, count: 5 })
    expect(d.allow).toBe(true)
    expect(d.newCount).toBe(6)
    expect(d.newLatchedUntil).toBe(0)
  })

  it('first sight (undefined state) allows — fail-open', () => {
    const d = ipDecision({ now: 1000, windowStart: undefined, count: undefined, latchedUntil: undefined })
    expect(d.allow).toBe(true)
    expect(d.newWindowStart).toBe(1000)
    expect(d.newCount).toBe(1)
  })

  it('crossing IP_LIMIT denies and sets a block for BLOCK_TTL_MS', () => {
    const d = ipDecision({ now: 2000, windowStart: 2000, count: IP_LIMIT })
    expect(d.newCount).toBe(IP_LIMIT + 1)
    expect(d.allow).toBe(false)
    expect(d.newLatchedUntil).toBe(2000 + BLOCK_TTL_MS)
  })

  it('an active latch denies without recounting', () => {
    const d = ipDecision({ now: 3000, windowStart: 3000, count: 10, latchedUntil: 9999 })
    expect(d.allow).toBe(false)
    expect(d.newCount).toBe(10)           // unchanged — no increment while latched
    expect(d.newLatchedUntil).toBe(9999)  // latch preserved
  })

  it('rolls the window when it has expired, resetting the count', () => {
    const d = ipDecision({ now: 1000 + WINDOW_MS, windowStart: 1000, count: 59 })
    expect(d.newWindowStart).toBe(1000 + WINDOW_MS)
    expect(d.newCount).toBe(1)
    expect(d.allow).toBe(true)
  })
})
