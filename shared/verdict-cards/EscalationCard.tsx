// EscalationCard.tsx — the CLIENT register (spec §3.2): the tally made literal,
// a type-appropriate hero, and the attributed ledger — a clean, FACTUAL artifact
// the analyst pastes into an escalation and annotates in the email body. Honesty
// here is structure (every claim attributed, no synthesized verdict, honest
// empties), NOT disclaimer prose — the analyst owns the nuance in the email.
//
// One skeleton drives every type. Hashes and CVEs are BANNER-LED (single-source
// authority, not a vote): the identity/exploitation hero leads and the cross-
// source tally is suppressed (hash carve-out, spec §3.1 / §5). Everything else
// leads with the tally-as-coverage headline + the segmented gauge, then the hero.
// All wording/banding comes from the verdict-lib doctrine.

import { useState, type ReactNode } from 'react'
import type { VerdictData } from '../verdict'
import { coverageState, dualUseTag, hashHeadline, leadFact } from '../verdict'
import { Chip, Divider, MicroLabel, type ChipVariant } from '../ui'
import { cveLead, isBannerLed } from '../card/model'
import { Hero } from './heroes'
import { CompareIp, type CompareResult } from './CompareIp'
import { CardActions } from './CardActions'
import { ContextList, IndicatorLine, SegGauge, SourceLedger, TallyHeadline } from './ui'
import type { CanvasTheme } from '../card/palette'

function queriedStamp(iso: string): string {
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return '—'
  return d.toISOString().replace('T', ' ').slice(0, 16) + ' UTC'
}

/** Hosting / VPN / datacenter flag from AbuseIPDB's usage type — the other big
 *  impossible-travel false-positive besides Tor (which the dual-use chip carries).
 *  Context, not a verdict. */
function networkChip(data: VerdictData): string | null {
  const usage =
    data.sources.find((s) => s.name === 'AbuseIPDB')?.facts?.find((f) => /usage type/i.test(f[0]))?.[1] ?? ''
  return /data ?cent(er|re)|hosting|vpn|cdn|transit|cloud/i.test(usage) ? 'hosting / datacenter' : null
}

/** Pulse count at which OTX community attention graduates from a neutral note to
 *  an amber "worth a look". Below it, periwinkle; at zero, no chip at all. */
const OTX_ATTENTION_MIN = 10

/** OTX community-pulse attention chip — surfaces the pulse count where the eye
 *  lands so a 50-report signal isn't buried as a neutral context row, WITHOUT
 *  entering the "N of M flagged" tally (pulse counts are community-submitted;
 *  this is attention, not a verdict). Graduates by count — periwinkle for a few,
 *  amber past OTX_ATTENTION_MIN. Null at zero (OTX stays a quiet context row).
 *  Owner-approved (2026-08-20), extending the reserved-colour evolution — amber
 *  reads "worth a look", never "flagged". */
function otxSignal(data: VerdictData): { label: string; variant: ChipVariant } | null {
  const otx = data.context.find((c) => /otx|alienvault/i.test(c.name))
  const raw = otx?.facts?.find((f) => /pulses/i.test(f[0]))?.[1]
  const count = parseInt(String(raw ?? '').replace(/[^\d]/g, ''), 10)
  if (!Number.isFinite(count) || count < 1) return null
  return {
    label: `OTX · ${count} pulse${count === 1 ? '' : 's'}`,
    variant: count >= OTX_ATTENTION_MIN ? 'suspicious' : 'accent',
  }
}

export function EscalationCard({
  data,
  theme,
  baseUrl,
  onCompare,
  /** Web-only reporting affordance (a ReportButton). Rendered in the header
   *  action row after CardActions, behind a vertical Divider. Only Lookup.tsx
   *  passes it; every other consumer omits it and renders unchanged. */
  reportSlot,
}: {
  data: VerdictData
  theme?: CanvasTheme
  /** Enrich origin for the inline Compare-IP lookup — undefined = same-origin
   *  (the web app); the extension passes its configured SOCDesk origin. */
  baseUrl?: string
  /** Fired whenever the inline Compare-IP result changes (payload on success,
   *  null on clear). The landing page uses this to draw the two-IP great-circle
   *  arc on the hero globe; other surfaces omit it. */
  onCompare?: (c: CompareResult | null) => void
  reportSlot?: ReactNode
}) {
  // A successful inline Compare-IP lifts its result here so the geo hero draws the
  // arc + second pin and the copy-card PNG bundles the same compare. Null for every
  // non-IP card (CompareIp is only rendered for IPs) and until a compare succeeds.
  const [compare, setCompare] = useState<CompareResult | null>(null)
  const banner = isBannerLed(data)
  const lead = banner ? null : leadFact(data.sources)
  const showStrongest = lead && data.band !== 'green' && data.band !== 'grey'
  const bannerHeadline = data.identityLed ? hashHeadline(data) : data.type === 'cve' ? cveLead(data) : ''
  const dualUseChip = dualUseTag(data.sources)
  const network = networkChip(data)
  const cov = coverageState(data.sources)
  const otx = otxSignal(data)

  return (
    <div className="overflow-hidden rounded-lg border border-line-bright bg-panel shadow-e2">
      <div className="h-0.5 bg-accent" />
      <div className="flex flex-col gap-3.5 p-4">
        <div className="flex flex-wrap items-center gap-2">
          <MicroLabel tone="accent">Escalation draft</MicroLabel>
          <span className="font-mono text-micro text-faint">SOCDESK · TRIAGE</span>
          <div className="ml-auto flex items-stretch gap-2">
            <CardActions data={data} theme={theme} compare={compare} />
            {reportSlot && (
              <>
                <Divider orientation="vertical" className="self-stretch" />
                <div className="flex items-center">{reportSlot}</div>
              </>
            )}
          </div>
        </div>

        <IndicatorLine data={data} />

        <div className="flex flex-col gap-2">
          <MicroLabel tone="muted">Assessment</MicroLabel>
          {banner ? (
            <p className="font-display text-base font-bold leading-snug text-paper">{bannerHeadline}</p>
          ) : (
            <TallyHeadline data={data} />
          )}
          {!banner && <SegGauge data={data} />}
          {!banner && cov.guard && <p className="font-mono text-micro text-faint">{cov.guard}</p>}
          {(dualUseChip || network || otx || data.band === 'grayware') && (
            <div className="flex flex-wrap items-center gap-1.5">
              {dualUseChip && <Chip variant="suspicious">{dualUseChip}</Chip>}
              {data.band === 'grayware' && <Chip variant="grayware">grayware — not malware</Chip>}
              {network && <Chip variant="neutral">{network}</Chip>}
              {otx && <Chip variant={otx.variant}>{otx.label}</Chip>}
            </div>
          )}
          {showStrongest && lead && (
            <p className="text-xs leading-relaxed text-muted">
              <span className="font-semibold text-paper">Lead source:</span> {lead.phrasing}.
            </p>
          )}
        </div>

        <Hero data={data} compare={compare} />

        {(data.type === 'ipv4' || data.type === 'ipv6') && (
          <CompareIp
            data={data}
            baseUrl={baseUrl}
            onResult={(c) => {
              setCompare(c)
              onCompare?.(c)
            }}
          />
        )}

        <div className="flex flex-col gap-2">
          <MicroLabel tone="muted">Evidence — attributed to public sources</MicroLabel>
          <SourceLedger data={data} />
        </div>

        <ContextList data={data} />

        <p className="font-mono text-micro text-faint">
          Generated by SOCDesk · sources queried {queriedStamp(data.checkedAt)}
        </p>
      </div>
    </div>
  )
}
