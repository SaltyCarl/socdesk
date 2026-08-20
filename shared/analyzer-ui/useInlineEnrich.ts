import { useEffect, useState } from 'react'
import { detectType, isEnrichable, refang } from '@socdesk/shared/indicators'
import { fetchEnrich, type VerdictData } from '@socdesk/shared/verdict'

export type InlineEnrichState =
  | { kind: 'idle' }
  | { kind: 'checking'; indicator: string }
  | { kind: 'ok'; indicator: string; data: VerdictData }
  | { kind: 'declined'; indicator: string; reason: string }
  | { kind: 'unavailable'; indicator: string; reason: string }
  | { kind: 'unsupported'; indicator: string }

/** Pure first state: only an enrichable indicator triggers a fetch; anything
 *  else (empty / CVE / email / unclassifiable) is terminal. Extracted so the
 *  classification is testable without rendering the hook. */
export function inlineInitialState(raw: string): InlineEnrichState {
  const indicator = raw ? refang(raw) : ''
  if (!indicator) return { kind: 'idle' }
  return isEnrichable(detectType(indicator))
    ? { kind: 'checking', indicator }
    : { kind: 'unsupported', indicator }
}

/** Resolve ONE extracted IOC to a card-ready state through the shared enrich
 *  client. `baseUrl` selects the origin (same-origin on the web, the configured
 *  SOCDesk origin in the extension). Only `indicator` — never any surrounding
 *  script — reaches /api/enrich. */
export function useInlineEnrich(raw: string, baseUrl?: string): InlineEnrichState {
  const [state, setState] = useState<InlineEnrichState>(() => inlineInitialState(raw))
  useEffect(() => {
    const first = inlineInitialState(raw)
    setState(first)
    if (first.kind !== 'checking') return
    let live = true
    void fetchEnrich(detectType(first.indicator), first.indicator, baseUrl ? { baseUrl } : undefined).then((o) => {
      if (!live) return
      if (o.status === 'ok') setState({ kind: 'ok', indicator: first.indicator, data: o.data })
      else if (o.status === 'declined') setState({ kind: 'declined', indicator: first.indicator, reason: o.reason })
      else setState({ kind: 'unavailable', indicator: first.indicator, reason: o.reason })
    })
    return () => { live = false }
  }, [raw, baseUrl])
  return state
}
