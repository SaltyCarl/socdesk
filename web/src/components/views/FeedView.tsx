import { useDeferredValue, useMemo, useState } from 'react'
import { cx } from '@socdesk/shared/lib/cx'
import { StoryStrip } from './StoryStrip'
import type { FeedItem, Story } from './types'
import { rel, safeUrl, num, pct } from './format'
import { KevBadge, DataChip, ClaimsChip } from './Badges'
import { EmptyState } from './states'
import { VictimLogo } from './VictimLogo'
import { claimCount } from '../overview/aggregations'
import { ActorLink, CveLink } from '../overview/board-ui'

/**
 * The feed is a BRIEFING, not a console. "The Brief" (approved Direction 1):
 * a dated masthead, ONE featured lead story with real emphasis, then the rest
 * organised into clean, category-grouped sections (Vulnerabilities · Ransomware
 * · Named actors · Malware · Reports) — each with a periwinkle line-glyph, a
 * live count, a "View all →", and scannable item rows.
 *
 * Two modes, one lens bar:
 *   • ALL + no search  → the full briefing (featured lead + every section).
 *   • a lens selected, OR an active search  → that scope as a flat, ranked list
 *     (a section's "View all →" just selects its lens). Search + honest empties
 *     are preserved in both.
 *
 * Every signal chip (KEV / EPSS / CVSS / N claims) is PARSED from the pipeline's
 * real `why` rationale — nothing is fabricated. Sources are attributed to the
 * upstream authority (CISA KEV, ransomware.live, or the outlet named in the
 * item's "[Outlet]" title prefix). Any empty scope states why.
 */

const INIT = 30
const STEP = 60
const SECTION_ROWS = 5

/* ---------------- lenses (curated groupings over raw categories) ---------- *
 * A lens can OR several categories ("Named actors" spans apt + campaign). The
 * ORDER here drives BOTH the lens bar and the briefing's section order (the
 * mockup's reading priority: exploited vulns → active ransomware → named actors
 * → malware → the long tail of reports). Each lens carries the periwinkle
 * line-glyph its section header wears. */
type GlyphName = 'vuln' | 'ransom' | 'actor' | 'campaign' | 'report' | 'bug'
type Lens = { key: string; label: string; categories: readonly string[]; glyph: GlyphName }

const LENSES: readonly Lens[] = [
  { key: 'vulnerabilities', label: 'Vulnerabilities', categories: ['vulnerability'], glyph: 'vuln' },
  { key: 'ransomware', label: 'Ransomware', categories: ['ransomware'], glyph: 'ransom' },
  { key: 'actors', label: 'Named actors', categories: ['apt', 'campaign'], glyph: 'actor' },
  { key: 'malware', label: 'Malware', categories: ['malware'], glyph: 'bug' },
  { key: 'reports', label: 'Reports', categories: ['report'], glyph: 'report' },
]

/** Per-category display identity for the lead eyebrow + the report-row glyph. */
const CAT_META: Record<string, { label: string; glyph: GlyphName }> = {
  vulnerability: { label: 'Vulnerability', glyph: 'vuln' },
  ransomware: { label: 'Ransomware', glyph: 'ransom' },
  apt: { label: 'Threat actor', glyph: 'actor' },
  campaign: { label: 'Campaign', glyph: 'campaign' },
  report: { label: 'Report', glyph: 'report' },
  malware: { label: 'Malware', glyph: 'bug' },
}
const catMeta = (cat: string) => CAT_META[cat] ?? { label: cat, glyph: 'report' as const }

/* ---------------- real-data helpers (pure) -------------------------------- */

const OUTLET_RE = /^\s*\[([^\]]+)\]\s*/

/** Structured signals parsed out of the pipeline's `why` rationale — the only
 *  place these facts live in feed.json (there are no raw epss/cvss/kev fields).
 *  `claims` is populated only for leak-site posts, so a non-ransomware row never
 *  shows a spurious "1 claim". */
interface Signals {
  kev: boolean
  epss: number | null
  cvss: number | null
  claims: number | null
}

function signalsFor(item: FeedItem): Signals {
  let kev = false
  let epss: number | null = null
  let cvss: number | null = null
  for (const w of item.why ?? []) {
    if (/KEV-listed/i.test(w)) kev = true
    const e = w.match(/EPSS\s+(\d+(?:\.\d+)?)\s*%/i)
    if (e) epss = Number(e[1]) / 100
    const c = w.match(/CVSS\s+(\d+(?:\.\d+)?)/i)
    if (c) cvss = Number(c[1])
  }
  const claims = item.source === 'ransomwarelive' ? claimCount(item) : null
  return { kev, epss, cvss, claims }
}

/** Attribute the upstream AUTHORITY, not the internal collector name. */
function sourceLabel(item: FeedItem): string {
  if (item.source === 'kev') return 'CISA KEV'
  if (item.source === 'ransomwarelive') return 'ransomware.live'
  if (item.source === 'rss') {
    const m = (item.title ?? '').match(OUTLET_RE)
    return m ? m[1] : 'RSS'
  }
  return item.source
}

/** Drop redundant chrome from the raw title — the "[Outlet]" prefix (the source
 *  chip carries it) and, for KEV rows, the "KEV: CVE-… — " lead-in (the KEV
 *  badge + the mono CVE id already carry it). Nothing is invented. */
function cleanTitle(item: FeedItem): string {
  let t = (item.title ?? '').replace(OUTLET_RE, '')
  if (item.source === 'kev') {
    t = t.replace(/^KEV:\s*/i, '')
    const cve = item.entities?.cves?.[0]
    if (cve) {
      const esc = cve.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
      t = t.replace(new RegExp(`^${esc}\\s*[—–-]\\s*`, 'i'), '')
    }
  }
  return t.trim()
}

/** The mono id shown in a row's left rail: a CVE for a vulnerability, the primary
 *  actor for a ransomware / actor row, else null (a category glyph stands in). */
function railActorName(item: FeedItem): string | null {
  if (item.category === 'ransomware' || item.category === 'apt' || item.category === 'campaign') {
    return item.entities?.actors?.[0] ?? null
  }
  return null
}
function cveId(item: FeedItem): string | null {
  return item.category === 'vulnerability' ? (item.entities?.cves?.[0] ?? null) : null
}

/** A ransomware.live item that names a specific victim renders VICTIM-FIRST:
 *  the org (with its logo + domain) is the attributed fact worth reading; the
 *  posting group is the claimant, already carried by the row's actor link. Null
 *  for non-leak or unnamed items, which keep the generic "{group} posted…" title.
 *  The victim/domain are pipeline-sanitized (ransomwarelive.py) inert text. */
function leakClaimVictim(item: FeedItem): { victim: string; domain?: string } | null {
  if (item.source !== 'ransomwarelive' || !item.victim) return null
  return { victim: item.victim, domain: item.domain }
}

/** Provenance line for a leak-site claim: the source is a Tor (.onion) leak
 *  site and the claim is unverified. Replaces the (deliberately) dead .onion
 *  link — the analyst sees WHERE it came from and that it isn't confirmed,
 *  without SOCDesk ever hyperlinking criminal infrastructure. */
function LeakProvenance() {
  return (
    <span className="font-mono text-micro text-faint">
      leak-site claim · .onion (Tor) · unverified
    </span>
  )
}

/** One decorated + pre-keyed item, so the priority sort keys are computed once. */
interface Ranked {
  item: FeedItem
  sig: Signals
  key: number[]
}

/** Priority key: the pipeline's 0–100 score dominates; ties break on KEV, then
 *  higher EPSS, higher CVSS, then recency — so at equal score the actively-
 *  exploited, most-likely-exploited CVE leads (reproduces the intended lead). */
function keyOf(item: FeedItem, sig: Signals): number[] {
  return [
    item.score ?? -1,
    sig.kev ? 1 : 0,
    sig.epss ?? -1,
    sig.cvss ?? -1,
    Date.parse(item.published_at ?? '') || 0,
  ]
}
function cmpDesc(a: Ranked, b: Ranked): number {
  for (let i = 0; i < a.key.length; i++) {
    if (b.key[i] !== a.key[i]) return b.key[i] - a.key[i]
  }
  return 0
}

function haystack(item: FeedItem): string {
  return (
    item.title +
    ' ' +
    item.summary +
    ' ' +
    Object.values(item.entities ?? {})
      .flat()
      .join(' ')
  ).toLowerCase()
}

/** Long-form briefing date from the snapshot's generated_at (falls back to the
 *  newest collected_at on the items). */
function briefingDate(iso?: string): string | null {
  if (!iso) return null
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return null
  return d.toLocaleDateString('en-US', {
    weekday: 'long',
    month: 'long',
    day: 'numeric',
    year: 'numeric',
  })
}

/* ---------------- periwinkle line-glyphs (UI, not severity) --------------- */

function Glyph({ name, className }: { name: GlyphName; className?: string }) {
  const common = {
    viewBox: '0 0 24 24',
    fill: 'none',
    stroke: 'currentColor',
    strokeWidth: 1.6,
    strokeLinecap: 'round' as const,
    strokeLinejoin: 'round' as const,
    'aria-hidden': true,
    className: cx('shrink-0', className),
  }
  switch (name) {
    case 'vuln':
      return (
        <svg {...common}>
          <path d="M12 3.5 5 6v5.2c0 5 3 8.6 7 9.8 4-1.2 7-4.8 7-9.8V6l-7-2.5Z" />
          <path d="M12 7.6v5.2" />
          <circle cx="12" cy="16.4" r="1" className="fill-current" stroke="none" />
        </svg>
      )
    case 'ransom':
      return (
        <svg {...common}>
          <rect x="5" y="11" width="14" height="9" rx="2" />
          <path d="M8 11V8a4 4 0 0 1 7.4-2.1" />
        </svg>
      )
    case 'actor':
      return (
        <svg {...common}>
          <circle cx="12" cy="12" r="6.6" />
          <path d="M12 2v3.4M12 18.6V22M2 12h3.4M18.6 12H22" />
          <circle cx="12" cy="12" r="1.3" className="fill-current" stroke="none" />
        </svg>
      )
    case 'campaign':
      return (
        <svg {...common}>
          <path d="M3 10.4v3.2h3.5l5.7 3.5V6.9l-5.7 3.5H3Z" />
          <path d="M15.4 9.2a4.7 4.7 0 0 1 0 5.6" />
          <path d="M18 6.5a8.6 8.6 0 0 1 0 11" />
        </svg>
      )
    case 'bug':
      return (
        <svg {...common}>
          <path d="M8 9a4 4 0 0 1 8 0v3a4 4 0 0 1-8 0V9Z" />
          <path d="M9.2 6.4 7.8 5M14.8 6.4 16.2 5M4 11h3M17 11h3M4.6 15.8 7 15M19.4 15.8 17 15M12 13v7.5" />
        </svg>
      )
    case 'report':
    default:
      return (
        <svg {...common}>
          <path d="M7 2.8h6.3L18 7.6v13.1a.5.5 0 0 1-.5.5h-10a.5.5 0 0 1-.5-.5V3.3a.5.5 0 0 1 .5-.5Z" />
          <path d="M13.3 2.8v4.3a.5.5 0 0 0 .5.5H18" />
          <path d="M9 12.3h6M9 15.6h6M9 9h2.4" />
        </svg>
      )
  }
}

/* ---------------- signal-chip cluster (shared by lead + rows) ------------- */

function SignalChips({ sig, className }: { sig: Signals; className?: string }) {
  const has = sig.kev || sig.epss != null || sig.cvss != null || sig.claims != null
  if (!has) return null
  return (
    <div className={cx('flex flex-wrap items-center gap-1.5', className)}>
      {sig.kev && <KevBadge />}
      {sig.epss != null && <DataChip label="EPSS" value={pct(sig.epss)} />}
      {sig.cvss != null && <DataChip label="CVSS" value={String(sig.cvss)} />}
      {sig.claims != null && <ClaimsChip count={sig.claims} />}
    </div>
  )
}

const ACTOR_CHIP =
  'inline-flex items-center rounded-sm border border-[var(--edge-accent)] bg-[var(--tint-accent)] px-1.5 py-0.5 font-mono text-micro font-semibold text-accent hover:underline'

/* ---------------- the featured lead --------------------------------------- */

function Lead({ item, sig }: { item: FeedItem; sig: Signals }) {
  const href = safeUrl(item.url)
  const meta = catMeta(item.category)
  const actors = item.entities?.actors ?? []
  const claim = leakClaimVictim(item)
  const title = cleanTitle(item)

  return (
    <article className="sd-reveal border-b border-line pb-9">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
        <span className="inline-flex items-center gap-2 text-xs font-semibold text-accent">
          <Glyph name={meta.glyph} className="size-4" />
          {meta.label}
        </span>
        {sig.kev && <KevBadge />}
      </div>

      <h2 className="mt-4 max-w-4xl font-display text-xl font-extrabold tracking-display text-paper sm:text-2xl">
        {claim ? (
          // Victim-first: the claimed org is the headline fact. .onion is never
          // a link, so this is always plain text — the group is the actor chip.
          claim.victim
        ) : href ? (
          <a
            href={href}
            target="_blank"
            rel="noopener noreferrer"
            className="underline-offset-4 transition-colors duration-150 ease-brand hover:text-accent hover:underline"
          >
            {title}
          </a>
        ) : (
          title
        )}
      </h2>

      {claim?.domain && (
        <p className="mt-2 font-mono text-sm text-faint">{claim.domain}</p>
      )}

      {item.summary && (
        <p className="mt-3 max-w-2xl text-md text-muted">{item.summary}</p>
      )}

      {claim && (
        <div className="mt-3">
          <LeakProvenance />
        </div>
      )}

      <div className="mt-5 flex flex-wrap items-center gap-x-3 gap-y-2">
        <SignalChips sig={{ ...sig, kev: false }} />
        <span className="text-sm font-semibold text-paper">{sourceLabel(item)}</span>
        <span aria-hidden="true" className="text-line-strong">
          ·
        </span>
        <span className="font-mono text-xs tabular-nums text-faint">
          {rel(item.published_at)}
        </span>
      </div>

      {actors.length > 0 && (
        <div className="mt-4 flex flex-wrap items-center gap-1.5">
          {actors.map((name) => (
            <ActorLink key={name} name={name} className={ACTOR_CHIP}>
              {name}
            </ActorLink>
          ))}
        </div>
      )}
    </article>
  )
}

/* ---------------- one scannable row --------------------------------------- */

function Row({ item, sig }: { item: FeedItem; sig: Signals }) {
  const href = safeUrl(item.url)
  const cve = cveId(item)
  const actor = railActorName(item)
  const actors = item.entities?.actors ?? []
  // The primary actor is already the left-rail link; don't repeat it as a chip.
  const extraActors = actor ? actors.filter((a) => a !== actor) : actors
  const claim = leakClaimVictim(item)
  const title = cleanTitle(item)

  return (
    <article className="grid gap-x-5 gap-y-2 border-b border-line py-4 last:border-0 sm:grid-cols-[7.5rem_minmax(0,1fr)_14rem] sm:items-start">
      {/* left rail — CVE id, primary actor link, or a category glyph. The CVE is
          the shared CveLink (SPA pivot into /lookup) with the rail's typography —
          it was a dead <span> here while a live link on the board, exactly the
          per-surface divergence the shared primitive exists to prevent. */}
      {cve ? (
        <CveLink
          cve={cve}
          className="break-words font-mono text-xs font-semibold tabular-nums text-accent-dim underline-offset-2 transition-colors duration-150 ease-brand hover:text-accent hover:underline sm:pt-0.5"
        />
      ) : actor ? (
        <ActorLink
          name={actor}
          className="break-words font-mono text-xs font-semibold text-accent-dim hover:text-accent hover:underline sm:pt-0.5"
        >
          {actor}
        </ActorLink>
      ) : (
        <span className="hidden size-8 items-center justify-center rounded-md border border-line bg-panel-soft sm:flex">
          <Glyph name={catMeta(item.category).glyph} className="size-4 text-accent" />
        </span>
      )}

      {/* the report */}
      <div className="min-w-0">
        {claim ? (
          // Victim-first: the claimed org (with its logo) is the fact; the group
          // is the left-rail actor link. .onion is never a link (see safeUrl).
          <div className="flex items-start gap-3">
            <VictimLogo domain={claim.domain} name={claim.victim} />
            <div className="min-w-0">
              <span className="block truncate text-base font-semibold text-paper">
                {claim.victim}
              </span>
              {claim.domain && (
                <span className="block truncate font-mono text-micro text-faint">
                  {claim.domain}
                </span>
              )}
            </div>
          </div>
        ) : href ? (
          <a
            href={href}
            target="_blank"
            rel="noopener noreferrer"
            className="text-base font-semibold text-paper underline-offset-2 transition-colors duration-150 ease-brand hover:text-accent hover:underline"
          >
            {title}
          </a>
        ) : (
          <span className="text-base font-semibold text-paper">{title}</span>
        )}
        {item.summary && (
          <p className="mt-1 line-clamp-2 text-xs text-muted">{item.summary}</p>
        )}
        {claim && (
          <div className="mt-1.5">
            <LeakProvenance />
          </div>
        )}
        {extraActors.length > 0 && (
          <div className="mt-2 flex flex-wrap items-center gap-1.5">
            {extraActors.map((name) => (
              <ActorLink key={name} name={name} className={ACTOR_CHIP}>
                {name}
              </ActorLink>
            ))}
          </div>
        )}
      </div>

      {/* signal + attribution */}
      <div className="flex flex-col gap-1.5 sm:items-end">
        <SignalChips sig={sig} className="sm:justify-end" />
        <div className="flex items-center gap-2">
          <span className="text-xs font-semibold text-paper">{sourceLabel(item)}</span>
          <span className="font-mono text-micro tabular-nums text-faint">
            {rel(item.published_at)}
          </span>
        </div>
      </div>
    </article>
  )
}

/* ---------------- section (briefing) -------------------------------------- */

function Section({
  lens,
  rows,
  total,
  onViewAll,
}: {
  lens: Lens
  rows: Ranked[]
  total: number
  onViewAll: () => void
}) {
  return (
    <section className="sd-reveal flex flex-col gap-2">
      <header className="flex items-center justify-between gap-4 border-b border-line-bright pb-3">
        <div className="flex items-center gap-2.5">
          <Glyph name={lens.glyph} className="size-5 text-accent" />
          <h3 className="font-display text-md font-bold tracking-tight text-paper">
            {lens.label}
          </h3>
          <span className="font-mono text-xs tabular-nums text-faint">{num(total)}</span>
        </div>
        {total > 0 && (
          <button
            type="button"
            onClick={onViewAll}
            className="inline-flex items-center gap-1 text-xs font-semibold text-accent underline-offset-2 transition-colors duration-150 ease-brand hover:text-accent-dim hover:underline focus-visible:outline-2 focus-visible:outline-accent"
          >
            View all
            <span aria-hidden="true">→</span>
          </button>
        )}
      </header>
      {rows.length === 0 ? (
        <p className="py-3 text-xs text-muted" role="status">
          No {lens.label.toLowerCase()} in this window.
        </p>
      ) : (
        <div className="flex flex-col">
          {rows.map(({ item, sig }) => (
            <Row key={item.id} item={item} sig={sig} />
          ))}
        </div>
      )}
    </section>
  )
}

/* ---------------- small controls ------------------------------------------ */

function LensChip({
  active,
  label,
  count,
  onClick,
}: {
  active: boolean
  label: string
  count: number
  onClick: () => void
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={active}
      className={cx(
        'inline-flex items-center gap-2 rounded-full border px-3 py-1.5 text-xs font-semibold transition-colors duration-150 ease-brand',
        'outline-offset-2 focus-visible:outline-2 focus-visible:outline-accent',
        active
          ? 'border-[var(--edge-accent)] bg-[var(--tint-accent)] text-accent'
          : 'border-line bg-panel text-muted hover:border-line-bright hover:text-paper',
      )}
    >
      {label}
      <span className="font-mono tabular-nums">{num(count)}</span>
    </button>
  )
}

/* ---------------- the view ------------------------------------------------ */

export function FeedView({
  items,
  generatedAt,
  stories = [],
}: {
  items: FeedItem[]
  generatedAt?: string
  stories?: Story[]
}) {
  const [filter, setFilter] = useState('all')
  const [limit, setLimit] = useState(INIT)
  const [rawQuery, setRawQuery] = useState('')
  const query = useDeferredValue(rawQuery)
  const q = query.trim().toLowerCase()

  // Decorate + priority-sort once; every downstream slice reuses this order.
  const ranked = useMemo<Ranked[]>(() => {
    return items
      .map((item) => {
        const sig = signalsFor(item)
        return { item, sig, key: keyOf(item, sig) }
      })
      .sort(cmpDesc)
  }, [items])

  // Lens bar: "All" first, then any lens with a live count (0-count lenses drop
  // out so the bar degrades honestly).
  const lenses = useMemo(() => {
    const counts = new Map<string, number>()
    for (const it of items) counts.set(it.category, (counts.get(it.category) ?? 0) + 1)
    const active = LENSES.map((l) => ({
      lens: l,
      count: l.categories.reduce((s, c) => s + (counts.get(c) ?? 0), 0),
    })).filter((l) => l.count > 0)
    return { all: items.length, active }
  }, [items])

  const showBriefing = filter === 'all' && !q

  // §3 corroborated stories: the highest-signal cross-source clusters (a delta or
  // ≥3 outlets, capped) lead the briefing. Their member reports are de-duped out
  // of the Lead/Sections so a corroborated item shows ONCE (as its story). Only
  // affects the briefing — list/search mode keeps the flat ranked slice.
  const featured = useMemo(
    () => stories.filter((s) => s.delta || s.outlets.length >= 3).slice(0, 6),
    [stories],
  )
  const shownMemberIds = useMemo(() => new Set(featured.flatMap((s) => s.member_ids)), [featured])
  const itemsById = useMemo(() => new Map(items.map((it) => [it.id, it])), [items])
  const rankedBriefing = useMemo(
    () => ranked.filter(({ item }) => !shownMemberIds.has(item.id)),
    [ranked, shownMemberIds],
  )

  // Featured lead = the highest-priority item NOT already surfaced as a story.
  const lead = rankedBriefing[0] ?? null

  // Briefing sections — top rows per lens, the lead + story members excluded.
  const sections = useMemo(() => {
    const leadId = lead?.item.id
    return LENSES.map((lens) => {
      const inLens = rankedBriefing.filter(({ item }) => lens.categories.includes(item.category))
      const rows = inLens.filter(({ item }) => item.id !== leadId).slice(0, SECTION_ROWS)
      return { lens, rows, total: inLens.length }
    }).filter((s) => s.total > 0)
  }, [rankedBriefing, lead])

  // List mode — a flat, ranked slice for a selected lens and/or an active search.
  const listItems = useMemo(() => {
    const allowed =
      filter === 'all' ? null : (LENSES.find((l) => l.key === filter)?.categories ?? null)
    return ranked.filter(
      ({ item }) =>
        (!allowed || allowed.includes(item.category)) && (!q || haystack(item).includes(q)),
    )
  }, [ranked, filter, q])

  const shown = listItems.slice(0, limit)
  const lensLabel = LENSES.find((l) => l.key === filter)?.label ?? 'All'

  const selectLens = (key: string) => {
    setFilter(key)
    setLimit(INIT)
  }

  const dateStr = briefingDate(generatedAt ?? items[0]?.collected_at)

  return (
    <div className="flex flex-col gap-8">
      {/* controls: search + lens bar */}
      <div className="flex flex-col gap-4">
        <input
          type="search"
          value={rawQuery}
          onChange={(e) => {
            setRawQuery(e.target.value)
            setLimit(INIT)
          }}
          placeholder="Search reports, CVEs, actors, vendors…"
          aria-label="Search the briefing"
          className="h-10 w-full max-w-md rounded-md border border-line bg-field px-3.5 text-base text-paper outline-offset-2 placeholder:text-faint focus-visible:outline-2 focus-visible:outline-accent"
        />
        <div className="flex flex-wrap gap-2">
          <LensChip
            active={filter === 'all'}
            label="All"
            count={lenses.all}
            onClick={() => selectLens('all')}
          />
          {lenses.active.map(({ lens, count }) => (
            <LensChip
              key={lens.key}
              active={filter === lens.key}
              label={lens.label}
              count={count}
              onClick={() => selectLens(lens.key)}
            />
          ))}
        </div>
      </div>

      {/* body */}
      {items.length === 0 ? (
        <EmptyState title="Nothing has been collected yet">
          The pipeline publishes on a schedule; the briefing fills on the next
          successful pull. Everything else on the desk still works.
        </EmptyState>
      ) : showBriefing ? (
        <div className="flex flex-col gap-10">
          {/* dated masthead */}
          <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1 border-b border-line pb-6">
            <p className="font-display text-md font-bold tracking-tight text-paper">
              {dateStr ?? 'Latest briefing'}
            </p>
            <p className="font-mono text-xs tabular-nums text-faint">
              {num(items.length)} reports tracked
            </p>
          </div>

          {featured.length > 0 && <StoryStrip stories={featured} itemsById={itemsById} />}

          {lead && <Lead item={lead.item} sig={lead.sig} />}

          <div className="flex flex-col gap-10">
            {sections.map(({ lens, rows, total }) => (
              <Section
                key={lens.key}
                lens={lens}
                rows={rows}
                total={total}
                onViewAll={() => selectLens(lens.key)}
              />
            ))}
          </div>
        </div>
      ) : listItems.length === 0 ? (
        <EmptyState title="No reports match this view">
          {q
            ? `Nothing in ${filter === 'all' ? 'the briefing' : lensLabel} matches “${query.trim()}”. Clear the search or switch lens — the collected reports are still here, just filtered out.`
            : `No ${lensLabel.toLowerCase()} in this window. Switch back to the “All” lens for the full briefing.`}
        </EmptyState>
      ) : (
        <div className="flex flex-col gap-4">
          <div className="flex items-center justify-between gap-4 border-b border-line pb-4">
            <div className="flex items-center gap-2.5">
              {filter !== 'all' && (
                <Glyph
                  name={LENSES.find((l) => l.key === filter)?.glyph ?? 'report'}
                  className="size-5 text-accent"
                />
              )}
              <h3 className="font-display text-md font-bold tracking-tight text-paper">
                {filter === 'all' ? 'Search results' : lensLabel}
              </h3>
              <span className="font-mono text-xs tabular-nums text-faint">
                {num(listItems.length)}
              </span>
            </div>
            {filter !== 'all' && (
              <button
                type="button"
                onClick={() => selectLens('all')}
                className="inline-flex items-center gap-1 text-xs font-semibold text-accent underline-offset-2 transition-colors duration-150 ease-brand hover:text-accent-dim hover:underline focus-visible:outline-2 focus-visible:outline-accent"
              >
                <span aria-hidden="true">←</span>
                Back to briefing
              </button>
            )}
          </div>

          <div className="flex flex-col">
            {shown.map(({ item, sig }) => (
              <Row key={item.id} item={item} sig={sig} />
            ))}
          </div>

          {listItems.length > limit && (
            <button
              type="button"
              onClick={() => setLimit((n) => n + STEP)}
              className="mx-auto rounded-md border border-line bg-panel px-4 py-2 text-xs font-semibold text-muted transition-colors duration-150 ease-brand hover:border-line-bright hover:text-paper focus-visible:outline-2 focus-visible:outline-accent"
            >
              Load more — {num(listItems.length - shown.length)} remaining
            </button>
          )}
        </div>
      )}
    </div>
  )
}
