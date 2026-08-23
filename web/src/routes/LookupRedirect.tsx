// LookupRedirect — /lookup is retired; the cockpit (/) is the single lookup
// surface. Preserves bookmarked/shared `/lookup#q=<x>` links by hard-redirecting
// to `/#q=<x>` (a full reload), so the cockpit fresh-loads and its
// useState(readLookupQuery) seed reads the hash — the same proven path as a
// direct /#q= load. A synthetic popstate does NOT work at cold mount: App's
// useRoute attaches its popstate listener in a parent useEffect that runs AFTER
// this child effect, so the event would fire to zero listeners. `/lookup#q=` is
// a rare external-bookmark path, so a reload is fine; `replace` (not assign)
// leaves no /lookup entry in history.
import { useLayoutEffect } from 'react'

export function LookupRedirect(): null {
  useLayoutEffect(() => {
    window.location.replace('/' + window.location.hash)
  }, [])
  return null
}
