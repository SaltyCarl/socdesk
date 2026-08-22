// useSession — Shell-level chrome (relocated from components/report). Probes
// GET /api/report/mine: 200 = signed in (echoing the GitHub login), anything
// else = signed out. Only guards the WRITE (report) path — the lookup/analyzer
// read path stays no-account.

import { useEffect, useState } from 'react'
import { markContributorSeen } from './contributorSeen'

export type SessionState = { status: 'loading' | 'in' | 'out'; login?: string }

/** Pure map of a probe (HTTP status + parsed body, or null on network/parse
 *  failure) to session state. Side-effect-free, so node-testable. */
export function sessionStateFrom(status: number, body: { login?: string } | null): SessionState {
  if (status === 200) return { status: 'in', login: body?.login }
  return { status: 'out' }
}

export function useSession(): SessionState {
  const [s, setS] = useState<SessionState>({ status: 'loading' })
  useEffect(() => {
    let live = true
    fetch('/api/report/mine', { credentials: 'same-origin' })
      .then(async (r) => {
        const body = await r.json().catch(() => null)
        if (live) {
          const next = sessionStateFrom(r.status, body)
          if (next.status === 'in') markContributorSeen()
          setS(next)
        }
      })
      .catch(() => {
        if (live) setS({ status: 'out' })
      })
    return () => {
      live = false
    }
  }, [])
  return s
}
