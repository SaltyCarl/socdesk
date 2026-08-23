// LookupRedirect — /lookup is retired; the cockpit (/) is the single lookup
// surface. Preserves bookmarked/shared `/lookup#q=<x>` links by rewriting to
// `/#q=<x>` (replaceState leaves no /lookup entry in history) and handing off
// to the cockpit, which reads the same `#q=` deep link (Overview.tsx sync).
import { useLayoutEffect } from 'react'

export function LookupRedirect(): null {
  // useLayoutEffect (not useEffect): the rewrite runs BEFORE paint, so a
  // cold-load `/lookup#q=x` bookmark never flashes a blank `default`-width main
  // frame before Overview (wide) mounts — the only time this component renders.
  useLayoutEffect(() => {
    const hash = window.location.hash // carries `#q=…` verbatim (or '')
    window.history.replaceState({}, '', '/' + hash)
    window.dispatchEvent(new PopStateEvent('popstate'))
  }, [])
  return null
}
