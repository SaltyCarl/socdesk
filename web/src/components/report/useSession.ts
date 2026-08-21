// useSession — a tiny hook reporting whether the analyst is signed in, by
// probing GET /api/report/mine (401 = signed out). Used by ReportForm to
// gate the report form behind a GitHub sign-in — the lookup/analyzer read
// path itself stays no-account; this only guards the WRITE (report) path.

import { useEffect, useState } from 'react'

export type SessionState = { status: 'loading' | 'in' | 'out' }

export function useSession(): SessionState {
  const [s, setS] = useState<SessionState>({ status: 'loading' })
  useEffect(() => {
    let live = true
    fetch('/api/report/mine', { credentials: 'same-origin' })
      .then((r) => {
        if (live) setS({ status: r.ok ? 'in' : 'out' })
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
