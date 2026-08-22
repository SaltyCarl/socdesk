// lib/__tests__/community_loader.test.mjs
// The Function-side dataset loader: reads the committed static asset, memoizes
// SUCCESSFUL loads only (a transient miss must NOT poison the per-isolate
// cache). Importing functions/api/enrich.js is safe under Node/vitest — it only
// references caches.default/Request/Response inside onRequestGet, not at load.
import { describe, expect, it } from 'vitest'
import { loadCommunity } from '../../functions/api/enrich.js'

/** An env whose ASSETS.fetch yields the next scripted step per call:
 *  'miss' -> a non-ok Response, 'throw' -> an exception, else -> ok+json(step). */
function scriptedAssets(steps) {
  let i = 0
  return { ASSETS: { fetch: async () => {
    const step = steps[Math.min(i++, steps.length - 1)]
    if (step === 'throw') throw new Error('asset store down')
    if (step === 'miss') return { ok: false, json: async () => ({}) }
    return { ok: true, json: async () => step }
  } } }
}

describe('loadCommunity (functions/api/enrich.js)', () => {
  it('memoizes successful loads only; a transient miss is retried, not cached', async () => {
    const data = { indicators: { 'ipv4|1.2.3.4': { type: 'ipv4' } } }
    const env = scriptedAssets(['miss', data, 'throw'])
    const origin = 'https://socdesk.io'
    // 1) transient miss -> null, NOT memoized
    expect(await loadCommunity(env, origin)).toBe(null)
    // 2) next call succeeds -> data returned + memoized
    expect(await loadCommunity(env, origin)).toEqual(data)
    // 3) even though the store now throws, the memoized success is served
    expect(await loadCommunity(env, origin)).toEqual(data)
  })
})
