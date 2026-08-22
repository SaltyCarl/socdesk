// contributorSeen — a one-bit hint that this browser has engaged the reporting
// write path at least once. The quiet account chrome (AccountControl) and its
// session probe are gated on it, so a browser that only ever looks up pays
// NOTHING (no DOM, no /api/report/mine call). SSR-safe: every storage touch is
// wrapped (private mode / no DOM throws), mirroring shared/lib/theme.ts.

const KEY = 'sd_contributor'

export function isContributorSeen(): boolean {
  try {
    return localStorage.getItem(KEY) === '1'
  } catch {
    return false
  }
}

export function markContributorSeen(): void {
  try {
    localStorage.setItem(KEY, '1')
  } catch {
    /* storage blocked — the chrome simply stays quiet this session */
  }
}
