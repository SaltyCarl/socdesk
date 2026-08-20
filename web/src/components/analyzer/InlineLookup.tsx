// InlineLookup — the escalation for ONE expanded IOC row inside the analyzer's
// IocTable. Resolves `raw` through the same `useLookup` hook the /lookup
// triptych and the landing inline card use, so only this one clicked
// indicator ever reaches `/api/enrich` — the analyzed command/script text
// that produced it is never sent (data boundary, unchanged).

import { EscalationCard } from '@socdesk/shared/verdict-cards'
import { useLookup } from '../lookup/useLookup'
import { LookupStatus } from '../lookup/LookupStates'
import { useEffectiveTheme } from '../lookup/useEffectiveTheme'

export function InlineLookup({ raw }: { raw: string }) {
  const state = useLookup(raw)
  const theme = useEffectiveTheme()
  if (state.kind === 'idle') return null
  if (state.kind === 'ok') {
    return <EscalationCard data={state.data} theme={theme} />
  }
  return <LookupStatus state={state} />
}
