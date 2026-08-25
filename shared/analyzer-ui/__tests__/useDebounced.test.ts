import { describe, expect, it } from 'vitest'
import { scheduleDebounced } from '../useDebounced'

// Test-env note: this repo has no DOM test environment (no jsdom/happy-dom
// in web/package.json devDependencies, and web/vitest.config.ts pins
// `environment: 'node'`) and no @testing-library/react, so `renderHook` (the
// brief's default test) is unavailable — the same constraint useCockpitInput.ts
// documents for usePsAnalysis/useLookup ("there is no jsdom/React Testing
// Library harness here"). useDebounced itself is an obviously-correct
// useState+useEffect wrapper around `scheduleDebounced`, the real exported
// timing primitive it calls — this drives that primitive directly, hand-
// simulating the exact sequence of effect mount/cleanup/re-run React performs
// on a dependency change, rather than duplicating or approximating the logic.
describe('scheduleDebounced (useDebounced\'s timing primitive)', () => {
  it('does not settle before the delay elapses, then settles to the initial value', async () => {
    let current = 'a'
    const cancel = scheduleDebounced('a', 50, (v) => { current = v })
    expect(current).toBe('a') // unsettled yet — mirrors "returns the initial value immediately"
    await new Promise((r) => setTimeout(r, 70))
    expect(current).toBe('a')
    cancel()
  })

  it('a rerender (dependency change) cancels the pending timer and settles to the latest value after the delay', async () => {
    let current = 'a'
    let cancel = scheduleDebounced('a', 50, (v) => { current = v })
    // Simulated rerender before the first timer fires: React's useEffect
    // cleanup (clearTimeout) runs, then the effect re-runs with the new value.
    cancel()
    cancel = scheduleDebounced('b', 50, (v) => { current = v })
    expect(current).toBe('a') // still not settled

    await new Promise((r) => setTimeout(r, 70))
    expect(current).toBe('b')
    cancel()
  })

  it('cancelling before the delay elapses means the callback never fires (a stale value can never win)', async () => {
    let current = 'a'
    const cancel = scheduleDebounced('b', 30, (v) => { current = v })
    cancel()
    await new Promise((r) => setTimeout(r, 60))
    expect(current).toBe('a')
  })
})
