import { useEffect, useState } from 'react'

/** The debounce timing primitive — pure `setTimeout` + cleanup, no React.
 *  Extracted so it can be unit-tested directly without a DOM renderer (this
 *  repo has no jsdom/happy-dom and no @testing-library/react — see
 *  useCockpitInput.ts's identical note about usePsAnalysis/useLookup).
 *  Returns a cancel function; calling it before `ms` elapses means
 *  `onSettle` never fires — matches what a `useEffect` cleanup does on a
 *  dependency change or unmount. */
export function scheduleDebounced<T>(value: T, ms: number, onSettle: (v: T) => void): () => void {
  const id = setTimeout(() => onSettle(value), ms)
  return () => clearTimeout(id)
}

/** Debounce a rapidly-changing value (analyzer input). Makes usePsAnalysis's
 *  "debounced-by-caller" contract true — the analyzer no longer re-tokenizes
 *  the whole corpus on every keystroke. Returns `value` immediately on
 *  mount/first render, then the latest `value` once `ms` has passed with no
 *  further change (a change before then cancels and restarts the wait). */
export function useDebounced<T>(value: T, ms: number): T {
  const [debounced, setDebounced] = useState(value)
  useEffect(() => scheduleDebounced(value, ms, setDebounced), [value, ms])
  return debounced
}
