// accountChrome — the Part A decision logic, kept pure (node-testable) and out
// of the component so the "quiet-until-relevant" doctrine is enforced at the
// data layer, not just visually.

import type { SessionState } from './useSession'

/** Gate the /api/report/mine probe: an unseen browser fires NOTHING. */
export function shouldProbeSession(seen: boolean): boolean {
  return seen
}

export type AccountView = 'none' | 'signin' | 'chip'

/** What the topbar renders, from the two gate signals. */
export function accountView(seen: boolean, status: SessionState['status']): AccountView {
  if (!seen) return 'none'
  if (status === 'in') return 'chip'
  if (status === 'out') return 'signin'
  return 'none' // loading → nothing (brief; no loading chrome)
}
