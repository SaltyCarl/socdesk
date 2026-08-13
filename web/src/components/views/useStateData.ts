// useStateData.ts — the one client-side fetch path for the data views.
//
// Every view reads a committed snapshot from /data/state/*.json (git is the
// datastore; there is no live backend for these surfaces). Same-origin fetch,
// so it satisfies the strict CSP `connect-src 'self'`. The hook resolves to a
// three-state machine — loading | ready | error — and the view derives its own
// "empty" from a ready-but-length-0 payload (absence of data is stated
// honestly, never rendered as a blank screen).

import { useEffect, useState } from 'react'

export type AsyncStatus = 'loading' | 'ready' | 'error'

export interface AsyncState<T> {
  status: AsyncStatus
  data: T | null
  /** A short, human reason when status==='error'. */
  error: string | null
}

/** Base-aware state-file URL. BASE_URL is '/' on Cloudflare Pages / Vite
 *  preview, so this resolves to /data/state/<name>.json. */
export function stateUrl(name: string): string {
  return `${import.meta.env.BASE_URL}data/state/${name}.json`
}

/**
 * Fetch and parse one state file. Aborts on unmount / name change so a slow
 * response can never resolve into an unmounted view. `cache: 'no-cache'`
 * mirrors the live site: always revalidate, the snapshot moves under us.
 */
export function useStateData<T>(name: string): AsyncState<T> {
  const [state, setState] = useState<AsyncState<T>>({
    status: 'loading',
    data: null,
    error: null,
  })

  useEffect(() => {
    const ctrl = new AbortController()
    let live = true
    setState({ status: 'loading', data: null, error: null })

    fetch(stateUrl(name), { cache: 'no-cache', signal: ctrl.signal })
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`)
        return r.json() as Promise<T>
      })
      .then((data) => {
        if (live) setState({ status: 'ready', data, error: null })
      })
      .catch((err: unknown) => {
        if (!live || ctrl.signal.aborted) return
        const msg = err instanceof Error ? err.message : 'fetch failed'
        setState({ status: 'error', data: null, error: msg })
      })

    return () => {
      live = false
      ctrl.abort()
    }
  }, [name])

  return state
}
