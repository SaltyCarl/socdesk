// ui.tsx — the shared, reserved-colour building blocks of the escalation card.
//
// These render the doctrine (verdict-lib) verbatim: the per-source verdict dot,
// the source-class chip (classTag), the tally-as-coverage headline
// (coverageHeadline), the segmented gauge, the attributed ledger, the context
// list, and the client-safe caveat (CAVEAT). Both registers — the client card
// and the analyst console — compose these, so wording + colour stay identical.
//
// COLOUR LAW: red/amber/green appear ONLY on verdict-severity marks; the accent
// is periwinkle (product); everything else is room-neutral. All classes are
// static Tailwind strings (CSP: no inline styles).

import type { Band, SourceClass, SourceVerdict, VerdictData, VerdictSource } from '../verdict'
import { CAVEAT, classTag, coverageHeadline, isStale, predicate } from '../verdict'
import { cx } from '../lib/cx'
import { Chip, MicroLabel, type ChipVariant } from '../ui'
import { gaugeCaption, gaugeSegments } from '../card/model'

const TYPE_LABEL: Record<VerdictData['type'], string> = {
  ipv4: 'IPv4',
  domain: 'Domain',
  url: 'URL',
  md5: 'MD5',
  sha1: 'SHA-1',
  sha256: 'SHA-256',
  cve: 'CVE',
  email: 'Email',
}

/** Per-source verdict dot ink (the only red/amber/green in the ledger). */
const DOT: Record<SourceVerdict, string> = {
  malicious: 'bg-verdict-red',
  suspicious: 'bg-verdict-amber',
  benign: 'bg-verdict-green',
  unknown: 'bg-faint',
}

/** One gauge segment, coloured by the source's own verdict. Benign is an
 *  outline (a source looked and found nothing), unknown is a neutral track
 *  (nothing to say — never green). */
const SEG: Record<SourceVerdict, string> = {
  malicious: 'bg-verdict-red border-verdict-red',
  suspicious: 'bg-verdict-amber border-verdict-amber',
  benign: 'border-verdict-green bg-transparent',
  unknown: 'border-line bg-panel-soft',
}

/** The doctrine band drives the headline count ink (decoupled from raw N/M). */
const BAND_INK: Record<Band, string> = {
  red: 'text-verdict-red',
  amber: 'text-verdict-amber',
  grayware: 'text-verdict-amber',
  green: 'text-verdict-green',
  grey: 'text-faint',
}

/** Source-class → chip variant (periwinkle/neutral by authority; never a
 *  verdict hue). KEV / authoritative membership rides the accent. */
const CLASS_VARIANT: Record<SourceClass, ChipVariant> = {
  catalog: 'catalog',
  authoritative: 'accent',
  behavioral: 'behavioral',
  score: 'reputation',
  list: 'list',
  unclassified: 'neutral',
}

function classChipVariant(s: VerdictSource): ChipVariant {
  return s.kev ? 'accent' : CLASS_VARIANT[s.class]
}

export function VerdictDot({ verdict }: { verdict: SourceVerdict }) {
  return (
    <span aria-hidden="true" className={cx('inline-block size-1.5 shrink-0 rounded-full', DOT[verdict])} />
  )
}

export function ClassChip({ source }: { source: VerdictSource }) {
  // An UNMAPPED source carries no class chip — it must never impersonate a
  // scored source (item 1). A KEV listing still shows its authoritative chip.
  if (source.class === 'unclassified' && !source.kev) return null
  return <Chip variant={classChipVariant(source)}>{classTag(source)}</Chip>
}

export function RecencyTag({ source, now }: { source: VerdictSource; now?: Date }) {
  if (!source.recency) return null
  // A catalog/identity or KEV membership does not go stale off a first-seen date
  // (item 5) — keep the "as of" date, drop the "· stale" marker so it never
  // contradicts the last-seen banner.
  const stale = isStale(source.recency, now) && source.class !== 'catalog' && !source.kev
  return (
    <span className="font-mono text-micro text-muted">
      as of {source.recency}
      {stale && <span className="ml-1 font-semibold text-verdict-amber">· stale</span>}
    </span>
  )
}

export function IndicatorLine({ data }: { data: VerdictData }) {
  return (
    <div className="flex items-baseline gap-2 border-b border-line pb-3">
      <span className="break-all font-mono text-base font-semibold text-paper">{data.indicator}</span>
      <Chip variant="neutral" className="shrink-0">
        {TYPE_LABEL[data.type]}
      </Chip>
    </div>
  )
}

/** Tally-as-coverage: leads with the count in the band ink, worded as coverage
 *  (a low/quiet tally reads "thin coverage", never "probably fine"). */
export function TallyHeadline({ data }: { data: VerdictData }) {
  const text = coverageHeadline(data.sources)
  const m = text.match(/^(\d+)(.*)$/s)
  return (
    <p className="font-display text-base font-bold leading-snug text-paper">
      {m ? (
        <>
          <b className={cx('font-black', BAND_INK[data.band])}>{m[1]}</b>
          {m[2]}
        </>
      ) : (
        text
      )}
    </p>
  )
}

/** Segmented gauge — one segment per consulted source, coloured by its finding.
 *  The count is made visual, still attributed (spec §3.2 client register). */
export function SegGauge({ data }: { data: VerdictData }) {
  const segs = gaugeSegments(data)
  const cap = gaugeCaption(data)
  return (
    <div className="flex flex-col gap-1.5">
      <div
        className="flex gap-[3px]"
        role="img"
        aria-label={`${data.flagged} of ${data.consulted} consulted sources flagged this`}
      >
        {segs.length ? (
          segs.map((v, i) => (
            <span key={`${v}-${i}`} className={cx('h-2.5 flex-1 rounded-sm border', SEG[v])} />
          ))
        ) : (
          <span className="h-2.5 flex-1 rounded-sm border border-line bg-panel-soft" />
        )}
      </div>
      <div className="flex justify-between font-mono text-micro text-faint">
        <span>{cap.left}</span>
        <span>{cap.right}</span>
      </div>
    </div>
  )
}

/** The attributed evidence ledger: every consulted source named, its finding as
 *  fact, its source-class chip, and its recency. A fixed-width left cell stacks
 *  the source name over its class chip (item 2), so every row's finding shares a
 *  stable left edge and the finding column stays wide even in the narrow landing
 *  card; the finding is LEFT-aligned in the remaining space, wrapped lines and
 *  the recency staying within that column (item 4). This mirrors the copy-card
 *  PNG's stacked name/chip column, and both registers (client + console) render
 *  identically. */
export function SourceLedger({ data, now }: { data: VerdictData; now?: Date }) {
  if (!data.sources.length) {
    return (
      <p className="rounded-md border border-line px-3 py-2 text-xs text-muted">
        No consulted source returned a finding.
      </p>
    )
  }
  return (
    <ul className="overflow-hidden rounded-md border border-line">
      {data.sources.map((s) => (
        <li
          key={s.name}
          className="flex items-start gap-3 border-b border-line px-3 py-2 last:border-0 even:bg-panel-soft/40"
        >
          <span className="flex w-[168px] shrink-0 flex-col items-start gap-1.5">
            <span className="flex w-full items-center gap-2">
              <VerdictDot verdict={s.verdict} />
              <span className="truncate font-sans text-xs font-semibold text-paper">{s.name}</span>
            </span>
            <ClassChip source={s} />
          </span>
          <span className="flex min-w-0 flex-1 flex-col gap-0.5 font-mono text-micro text-muted">
            <span className="min-w-0">{predicate(s)}</span>
            {s.recency && <RecencyTag source={s} now={now} />}
          </span>
        </li>
      ))}
    </ul>
  )
}

/** Context rows (geo/ASN) + named not-consulted sources. Never in the tally —
 *  silence about an unconsulted source would lie by omission. */
export function ContextList({ data }: { data: VerdictData }) {
  if (!data.context.length && !data.errors.length) return null
  // Same fixed left-cell width as the ledger (item 2): a dot-width spacer + name
  // in a 168px cell (context carries no source-class chip), so every context /
  // not-consulted finding aligns with the evidence findings above.
  return (
    <div className="flex flex-col gap-2">
      <MicroLabel tone="muted">Context — not a verdict</MicroLabel>
      <ul className="overflow-hidden rounded-md border border-line">
        {data.context.map((c) => (
          <li key={c.name} className="flex items-start gap-3 border-b border-line px-3 py-2 last:border-0">
            <span className="flex w-[168px] shrink-0 items-center gap-2">
              <span aria-hidden="true" className="inline-block size-1.5 shrink-0" />
              <span className="truncate font-sans text-xs font-semibold text-paper">{c.name}</span>
            </span>
            <span className="min-w-0 flex-1 font-mono text-micro text-muted">{c.finding}</span>
          </li>
        ))}
        {data.errors.length > 0 && (
          <li className="flex items-start gap-3 px-3 py-2">
            <span className="flex w-[168px] shrink-0 items-center gap-2">
              <span aria-hidden="true" className="inline-block size-1.5 shrink-0" />
              <span className="truncate font-sans text-xs font-semibold text-muted">Not consulted</span>
            </span>
            <span className="min-w-0 flex-1 font-mono text-micro text-faint">
              {data.errors.map((e) => `${e.source} (${e.reason})`).join(' · ')}
            </span>
          </li>
        )}
      </ul>
    </div>
  )
}

/** The client-safe caveat, verbatim from doctrine — travels on every card. */
export function Caveat() {
  return (
    <p className="border-l-2 border-line-strong pl-3 text-xs leading-relaxed text-muted">{CAVEAT}</p>
  )
}
