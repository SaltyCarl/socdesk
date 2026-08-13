// AnalystVerdict.tsx — the ANALYST register (spec §3.2): dense, in-context, for
// the console + extension. A plain N / M fraction and the attributed source
// table with class tags + recency — no bespoke hero glyph (the Muster is LARP as
// a hero; at most an inline sparkline in a multi-row list). Same doctrine, same
// reserved colours; just tighter and information-first.

import type { VerdictData } from '../../lib/verdict'
import { hashHeadline, leadFact } from '../../lib/verdict'
import { Chip, MicroLabel, Panel } from '../ui'
import { cveLead, isBannerLed } from './model'
import { ContextList, IndicatorLine, SourceLedger, TallyHeadline } from './ui'

export function AnalystVerdict({ data }: { data: VerdictData }) {
  const banner = isBannerLed(data)
  const lead = leadFact(data.sources)
  const showLead = !banner && lead && data.band !== 'green' && data.band !== 'grey'

  return (
    <Panel>
      <div className="flex flex-col gap-3">
        <div className="flex items-center justify-between gap-2">
          <MicroLabel tone="accent" tick>
            Analyst console
          </MicroLabel>
          {!banner && (
            <Chip variant="accent" pill>
              {data.flagged} / {data.consulted} sources
            </Chip>
          )}
        </div>

        <IndicatorLine data={data} />

        {banner ? (
          <p className="text-xs leading-relaxed text-muted">
            {data.identityLed ? hashHeadline(data) : cveLead(data)}
          </p>
        ) : (
          <TallyHeadline data={data} />
        )}

        {showLead && lead && (
          <p className="text-xs text-muted">
            <span className="font-semibold text-paper">Lead:</span> {lead.phrasing}.
          </p>
        )}

        <SourceLedger data={data} dense />
        <ContextList data={data} />
      </div>
    </Panel>
  )
}
