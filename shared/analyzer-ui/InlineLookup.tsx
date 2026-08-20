import { EscalationCard, useEffectiveTheme } from '@socdesk/shared/verdict-cards'
import { useInlineEnrich } from './useInlineEnrich'
import { InlineLookupStatus } from './InlineLookupStatus'

/** One expanded IOC row's escalation. Resolves `raw` through the lean shared
 *  enrich path (only the clicked IOC reaches /api/enrich; never the analyzed
 *  script). `baseUrl` is same-origin on the web, the configured origin in the
 *  extension. */
export function InlineLookup({ raw, baseUrl }: { raw: string; baseUrl?: string }) {
  const state = useInlineEnrich(raw, baseUrl)
  const theme = useEffectiveTheme()
  if (state.kind === 'idle') return null
  if (state.kind === 'ok') return <EscalationCard data={state.data} theme={theme} baseUrl={baseUrl} />
  return <InlineLookupStatus state={state} />
}
