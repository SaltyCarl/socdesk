import { useEffect, useState } from 'react'
import { analyze } from '@socdesk/shared/analyzer'
import type { AnalysisResult } from '@socdesk/shared/analyzer'

export type PsState =
  | { kind: 'idle' }
  | { kind: 'analyzing' }
  | { kind: 'ok'; result: AnalysisResult }
  | { kind: 'error'; message: string }

/** Runs the deterministic analyzer on the (debounced-by-caller) input. Guards
 *  against out-of-order completion — only the latest run updates state. */
export function usePsAnalysis(input: string): PsState {
  const [state, setState] = useState<PsState>({ kind: 'idle' })
  useEffect(() => {
    const q = input.trim()
    if (!q) { setState({ kind: 'idle' }); return }
    let live = true
    setState({ kind: 'analyzing' })
    analyze(q)
      .then((result) => { if (live) setState({ kind: 'ok', result }) })
      .catch((e) => { if (live) setState({ kind: 'error', message: e instanceof Error ? e.message : 'analysis failed' }) })
    return () => { live = false }
  }, [input])
  return state
}
