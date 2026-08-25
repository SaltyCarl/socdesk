import { useMemo, useState } from 'react'
import { cx } from '@socdesk/shared/lib/cx'
import { MicroLabel } from '../ui'
import { MonoTag } from './Badges'
import { rel, safeUrl, num } from './format'
import { intelSource } from './intelSource'
import { faviconSrc, monogram } from './logo'
import { PIVOTABLE, provenance, techniqueUrl } from './relations'
import { ActorLink, BoardPanel, CveLink, PanelEmpty } from '../overview/board-ui'
import type { ProfileResult, TimelineBucket } from './profiles'
import type { ClaimedVictim, RansomIntel } from './types'

/**
 * ActorProfile — the fused info-card for one threat actor / ransomware group /
 * malware family, addressed by `/actor#g=<slug>`.
 *
 * Honesty doctrine (shared/verdict/doctrine.ts): SOCDesk emits no verdict of its
 * own and never synthesises intelligence. Every section degrades to a DISTINCT
 * honest empty — no fingerprint, no leak-site activity, no reporting, no
 * relations are each stated in their own words rather than hidden or faked. The
 * claimed-victim list is UNVERIFIED, republished leak-site attribution — framed
 * as the group's own claim, never a SOCDesk finding.
 */

/* ---------------- small building blocks ---------------- */

function SectionLabel({ children, accent = false }: { children: React.ReactNode; accent?: boolean }) {
  return (
    <MicroLabel tone={accent ? 'accent' : 'faint'} tick={accent}>
      {children}
    </MicroLabel>
  )
}

/** An external link, with .onion / leak-site sources marked plainly. */
function ExternalLink({
  href,
  children,
  onion = false,
}: {
  href: string
  children: React.ReactNode
  onion?: boolean
}) {
  return (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      className="inline-flex items-center gap-1 text-xs text-accent underline-offset-2 hover:underline"
    >
      {children}
      <span aria-hidden="true">{onion ? '· .onion ↗' : '↗'}</span>
    </a>
  )
}

function TechniqueChip({ id }: { id: string }) {
  return (
    <a
      href={techniqueUrl(id)}
      target="_blank"
      rel="noopener noreferrer"
      className="rounded-sm border border-line bg-panel-soft px-1.5 py-0.5 font-mono text-micro text-muted transition-colors duration-150 ease-brand hover:border-line-bright hover:text-accent"
    >
      {id}
    </a>
  )
}

/** Software / malware chip. Cross-links into the profile system when the named
 *  tool is itself an addressable profile; otherwise a plain neutral chip. */
function SoftwareChip({ name, linkable }: { name: string; linkable: boolean }) {
  const base =
    'rounded-sm border border-line bg-panel-soft px-1.5 py-0.5 font-mono text-micro text-muted'
  return linkable ? (
    <ActorLink name={name} className={cx(base, 'hover:border-line-bright hover:text-accent')}>
      {name}
    </ActorLink>
  ) : (
    <span className={base}>{name}</span>
  )
}

function AliasChips({ aliases }: { aliases: string[] }) {
  if (!aliases.length) return null
  return (
    <div className="flex flex-wrap gap-1.5">
      {aliases.map((a) => (
        <span
          key={a}
          className="rounded-sm border border-line bg-panel px-1.5 py-0.5 font-mono text-micro text-faint"
        >
          {a}
        </span>
      ))}
    </div>
  )
}

/* ---------------- identity header ---------------- */

/** One key/value fact on the identity rail — mono, terse, analyst-grade. */
function Fact({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-1">
      <span className="font-mono text-micro uppercase tracking-label text-faint">{label}</span>
      <span className="font-mono text-xs text-paper">{children}</span>
    </div>
  )
}

function KindBadges({ profile }: { profile: ProfileResult }) {
  const fp = profile.fingerprint
  const isApt = !fp && !profile.ransomware && profile.reporting.length > 0
  return (
    <div className="flex flex-wrap items-center gap-1.5">
      {profile.ransomware && <MonoTag tone="accent">Ransomware group</MonoTag>}
      {profile.intel && (
        <MonoTag tone="accent">{intelSource(profile.intel.advisory?.url).org} seeded</MonoTag>
      )}
      {/* One consistent "ATT&CK <id>" treatment regardless of actor vs. malware
          kind — the metadata rail below no longer repeats it (dedupe). */}
      {fp?.attack_id && <MonoTag tone="muted">ATT&amp;CK {fp.attack_id}</MonoTag>}
      {isApt && <MonoTag tone="muted">APT · reported</MonoTag>}
    </div>
  )
}

/** The identity block: classification badges (incl. the single ATT&CK-id
 *  treatment), aliases, the ATT&CK deep-link, and a rail of status FACTS
 *  (first-seen, RaaS, victim count, slug) — each stated only when known,
 *  never synthesised. The actor's NAME itself is not repeated here — it is
 *  the page H1 immediately above this card (ActorProfileRoute), so restating
 *  it at similar weight would be a pure duplicate. The claim-count tally
 *  likewise lives only in the activity panel below, not twice at hero
 *  weight. */
function IdentityHeader({ profile }: { profile: ProfileResult }) {
  const { fingerprint, intel } = profile
  const attackHref = safeUrl(fingerprint?.attackUrl)
  const aliases = fingerprint?.aliases ?? intel?.aliases ?? []

  return (
    <header className="flex flex-col gap-4 rounded-lg border border-line bg-raised p-5 shadow-e1">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="flex min-w-0 flex-col gap-2">
          <KindBadges profile={profile} />
          {aliases.length > 0 && <AliasChips aliases={aliases} />}
        </div>

        {attackHref && (
          <a
            href={attackHref}
            target="_blank"
            rel="noopener noreferrer"
            className="shrink-0 font-mono text-micro text-accent underline-offset-2 hover:underline"
          >
            {fingerprint?.attack_id} on ATT&amp;CK ↗
          </a>
        )}
      </div>

      <div className="flex flex-wrap gap-x-6 gap-y-3 border-t border-line pt-4">
        {intel?.first_seen && <Fact label="First seen">{intel.first_seen}</Fact>}
        {intel && <Fact label="RaaS">{intel.raas ? 'Yes · affiliate model' : 'No'}</Fact>}
        {aliases.length > 0 && <Fact label="Aliases">{num(aliases.length)}</Fact>}
        <Fact label="Slug">g={profile.slug}</Fact>
      </div>
    </header>
  )
}

/* ---------------- leak-site activity (timeline + geography) ---------------- */

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']

/** ISO `YYYY-MM-DD` → terse `Mon D`, from the string parts only (deterministic,
 *  no Date/locale — the timeline weeks are already UTC Monday keys). */
function weekLabel(iso: string): string {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(iso)
  if (!m) return iso
  return `${MONTHS[Number(m[2]) - 1] ?? m[2]} ${Number(m[3])}`
}

/** Deterministic inline-SVG column chart of weekly claim volume — no chart
 *  dependency. Every bar is the same reserved-accent shade (periwinkle is the
 *  established claim-VOLUME colour, per ClaimsChip — a count, never a
 *  verdict) at full strength; the peak week is called out in the caption
 *  row instead of a second opacity/shade, so there is exactly one accent
 *  tone on the chart in either theme. Bar width and gap are fixed in chart
 *  units and the sequence is LEFT-anchored, so a sparse 2-3-week window
 *  clusters near the left on a baseline that still spans the full card,
 *  rather than a couple of bars stretching to fill the width. Each bar
 *  carries a native <title> for hover/keyboard, and the whole chart carries
 *  an aria summary. Static by design (no entrance animation) so it renders
 *  identically every time and needs no reduced-motion guard. */
function TimelineChart({ buckets }: { buckets: TimelineBucket[] }) {
  // Cap to the most recent 26 weeks (buckets arrive oldest-first): barW's
  // Math.max(2, …) floor below can't shrink past 2 chart units, so past
  // ~33 bars the fixed GAP alone would overflow the fixed 320-unit viewBox.
  // Unreachable today (30-day feed retention → ~5 buckets) but guarded in
  // case that retention constant ever grows.
  const data = buckets.filter((b) => b.week !== 'unknown').slice(-26)
  const W = 320
  const H = 76
  const padTop = 6
  const padBottom = 12
  const plotH = H - padTop - padBottom
  const max = Math.max(1, ...data.map((d) => d.count))
  const peak = data.reduce((a, b) => (b.count > a.count ? b : a), data[0])
  const total = data.reduce((s, d) => s + d.count, 0)

  // Fixed bar width + gap (chart units), left-anchored from x=0. Only shrinks
  // below the cap once enough weeks are packed in to need it — a 2-3 bar
  // window keeps the same bar width as a full one, just clustered left.
  const GAP = 8
  const MAX_BAR = 20
  const barW = Math.max(2, Math.min(MAX_BAR, (W - GAP * (data.length - 1)) / data.length))

  return (
    <div className="flex flex-col gap-1.5">
      <svg
        viewBox={`0 0 ${W} ${H}`}
        preserveAspectRatio="none"
        className="h-[76px] w-full"
        role="img"
        aria-label={`Weekly claim volume across ${data.length} weeks, peaking at ${peak.count} in the week of ${weekLabel(peak.week)}. ${total} claims total.`}
      >
        {/* baseline — always spans the full card width, even when the bars
            themselves cluster left for a sparse window */}
        <line
          x1={0}
          y1={padTop + plotH + 0.5}
          x2={W}
          y2={padTop + plotH + 0.5}
          className="stroke-line"
          strokeWidth={1}
          vectorEffect="non-scaling-stroke"
        />
        {data.map((d, i) => {
          const h = Math.max(d.count > 0 ? 2 : 0, (d.count / max) * plotH)
          const x = i * (barW + GAP)
          const y = padTop + plotH - h
          return (
            <rect key={d.week} x={x} y={y} width={barW} height={h} rx={1.5} className="fill-accent">
              <title>{`Week of ${weekLabel(d.week)}: ${d.count} claim${d.count === 1 ? '' : 's'}`}</title>
            </rect>
          )
        })}
      </svg>
      <div className="flex items-center justify-between font-mono text-micro text-faint">
        <span>{weekLabel(data[0].week)}</span>
        <span className="text-accent">peak {num(peak.count)}</span>
        <span>{weekLabel(data[data.length - 1].week)}</span>
      </div>
    </div>
  )
}

/** Sectors / countries the leak site attributed for a group — honest-empty per
 *  field, and countries carry the digest-partiality caveat the source forces. */
function GeoTags({ label, values, partial }: { label: string; values: string[]; partial?: boolean }) {
  return (
    <div className="flex flex-col gap-2">
      <SectionLabel>{label}</SectionLabel>
      {values.length ? (
        <>
          <div className="flex flex-wrap gap-1.5">
            {values.map((v) => (
              <MonoTag key={v} tone="ghost">
                {v}
              </MonoTag>
            ))}
          </div>
          {partial && (
            <p className="text-micro text-faint">
              Partial — rolled-up digest claims omit country, so more may be affected.
            </p>
          )}
        </>
      ) : (
        <p className="text-xs text-muted">None attributed by the source.</p>
      )}
    </div>
  )
}

function ActivityPanel({ activity }: { activity: NonNullable<ProfileResult['activity']> }) {
  const weeks = activity.timeline.filter((b) => b.week !== 'unknown')
  return (
    <div className="flex flex-col gap-5">
      <div className="flex items-end justify-between gap-4">
        <div className="flex flex-col gap-1">
          <SectionLabel>Victim claims · window</SectionLabel>
          <span className="font-display text-2xl font-extrabold tabular-nums text-paper">
            {num(activity.victimCount)}
          </span>
        </div>
        {weeks.length >= 2 && (
          <span className="font-mono text-micro text-faint">{num(weeks.length)} weeks</span>
        )}
      </div>

      {weeks.length >= 2 ? (
        <TimelineChart buckets={activity.timeline} />
      ) : (
        <p className="text-xs text-muted">
          Too few weeks in the window to chart a trend — the tally above is the window total.
        </p>
      )}

      <GeoTags label="Target sectors" values={activity.sectors} />
      <GeoTags label="Target countries" values={activity.countries} partial={activity.hasDigest} />
    </div>
  )
}

/* ---------------- initial access & detection (curated public-domain intel seed) --- */

/** Curated triage block sourced from a public-domain US federal advisory
 *  (CISA #StopRansomware or HHS HC3, per the schema's host gate — both 17
 *  U.S.C. §105 public domain): initial-access CVEs (pivot into our lookup),
 *  tools as hunting pivots, on-host attribution signals, the advisory figure
 *  (linked, public-domain), and a provenance footer. The attributing org and
 *  document type are derived from `intel.advisory.url`'s host (`intelSource`)
 *  — never hardcoded to a single publisher. Every fact attributed to the
 *  source; nothing synthesised. Absent entirely when the group is unseeded. */
function IntelPanel({ intel }: { intel: RansomIntel }) {
  const cves = intel.initial_access_cves ?? []
  const tools = intel.tools ?? []
  const notes = intel.ransom_note ?? []
  const exts = intel.extensions ?? []
  const sources = intel.sources ?? []
  const advisoryHref = safeUrl(intel.advisory?.url)
  const figureHref = safeUrl(intel.note_image)
  const source = intelSource(intel.advisory?.url ?? intel.note_image)
  const figureHost = figureHref ? new URL(figureHref).hostname : ''
  return (
    <div className="flex flex-col gap-5">
      <p className="text-xs leading-relaxed text-muted">
        Initial access, tooling and detection signals below are drawn from the group&rsquo;s{' '}
        {source.product} — attributed facts, not a SOCDesk assessment.
      </p>

      {cves.length > 0 && (
        <div className="flex flex-col gap-2">
          <SectionLabel accent>Known initial-access CVEs</SectionLabel>
          <div className="flex flex-wrap gap-1.5">
            {cves.map((c) => (
              <CveLink key={c} cve={c} />
            ))}
          </div>
          <p className="text-micro text-faint">Check whether these are exposed on the affected customer.</p>
        </div>
      )}

      {intel.raas && (
        <div className="rounded-r-sm border-l-2 border-[var(--edge-accent)] bg-[var(--tint-accent)] py-1.5 pl-3 pr-2">
          <p className="text-xs text-muted">
            <span className="font-semibold text-accent">RaaS</span> — affiliate TTPs vary per
            intrusion.
          </p>
        </div>
      )}

      {tools.length > 0 && (
        <div className="flex flex-col gap-2">
          <SectionLabel>Tooling — hunt for these in telemetry</SectionLabel>
          <div className="flex flex-wrap gap-1.5">
            {tools.map((t) => (
              <MonoTag key={t} tone="ghost">
                {t}
              </MonoTag>
            ))}
          </div>
        </div>
      )}

      {(notes.length > 0 || exts.length > 0) && (
        <div className="flex flex-col gap-2">
          <SectionLabel>On-host signatures</SectionLabel>
          {notes.length > 0 && (
            <p className="font-mono text-micro text-muted">
              ransom note: <span className="text-paper">{notes.join(', ')}</span>
            </p>
          )}
          {exts.length > 0 && (
            <p className="font-mono text-micro text-muted">
              extension: <span className="text-paper">{exts.join(', ')}</span>
            </p>
          )}
        </div>
      )}

      {figureHref && (
        <div className="flex flex-col gap-2">
          <SectionLabel>Ransom-note figure</SectionLabel>
          <ExternalLink href={figureHref}>View {source.org} advisory figure</ExternalLink>
          <p className="text-micro text-faint">
            {source.org} advisory image (public domain) — opens on {figureHost}.
          </p>
        </div>
      )}

      {intel.advisory && advisoryHref && (
        <ExternalLink href={advisoryHref}>
          {source.org} advisory {intel.advisory.id}
        </ExternalLink>
      )}

      {(intel.last_reviewed || intel.advisory_date || sources.length > 0) && (
        <div className="flex flex-col gap-2 border-t border-line pt-3">
          <p className="font-mono text-micro text-faint">
            {source.org} seed
            {intel.last_reviewed ? ` · reviewed ${intel.last_reviewed}` : ''}
            {intel.advisory_date ? ` · advisory ${intel.advisory_date}` : ''}
          </p>
          {sources.length > 0 && (
            <div className="flex flex-wrap gap-x-4 gap-y-1">
              {sources.map((s) => {
                const href = safeUrl(s.url)
                return href ? (
                  <ExternalLink key={s.id} href={href}>
                    {s.id}
                  </ExternalLink>
                ) : null
              })}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

/* ---------------- claimed victims (attributed leak-site facts) ------------ */

/** A victim org's favicon via the same-origin proxy, falling back to a brand-
 *  coloured monogram on any load error (or an absent/invalid domain). The proxy
 *  is what keeps the page CSP at `img-src 'self'` and the victim domain off any
 *  third-party CDN — see functions/api/favicon.js. */
function VictimLogo({ domain, name }: { domain?: string; name: string }) {
  const src = faviconSrc(domain)
  const [failed, setFailed] = useState(false)
  const monoBox =
    'flex h-7 w-7 shrink-0 items-center justify-center rounded-sm border border-[var(--edge-accent)] bg-[var(--tint-accent)] font-mono text-micro font-semibold text-accent'

  if (!src || failed) {
    return (
      <span aria-hidden="true" className={monoBox}>
        {monogram(name)}
      </span>
    )
  }
  return (
    <img
      src={src}
      alt=""
      width={28}
      height={28}
      loading="lazy"
      onError={() => setFailed(true)}
      // The proxy answers "no icon" with a 1×1 transparent PNG (a SUCCESSFUL
      // load, so onError never fires) — detect that sentinel on load and fall
      // back to the monogram, else the row shows an empty square.
      onLoad={(e) => {
        if (e.currentTarget.naturalWidth <= 1) setFailed(true)
      }}
      className="h-7 w-7 shrink-0 rounded-sm border border-line bg-panel-soft object-contain"
    />
  )
}

/** One claimed-victim ledger row. The claim link is a real link only for a
 *  clearnet URL; an .onion address is rendered as PLAIN, non-navigable text
 *  (never an anchor) — an analyst reads it, the app never routes to Tor. */
function VictimRow({ v }: { v: ClaimedVictim }) {
  const href = safeUrl(v.claimUrl)
  const onion = /\.onion(\/|$|:)/i.test(v.claimUrl)
  return (
    <div className="flex items-center gap-3 py-3 first:pt-0">
      <VictimLogo domain={v.domain} name={v.victim} />
      <div className="flex min-w-0 flex-1 flex-col gap-1">
        <div className="flex items-baseline justify-between gap-2">
          <span className="truncate text-base text-paper">{v.victim}</span>
          {v.date && (
            <span className="shrink-0 whitespace-nowrap font-mono text-micro text-faint">
              {rel(v.date)}
            </span>
          )}
        </div>
        {v.domain && <span className="truncate font-mono text-micro text-faint">{v.domain}</span>}
        <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
          {v.sector && <MonoTag tone="ghost">{v.sector}</MonoTag>}
          {v.country && <span className="font-mono text-micro text-faint">{v.country}</span>}
          {onion ? (
            <span className="font-mono text-micro text-faint">leak-site post · .onion (Tor)</span>
          ) : href ? (
            <ExternalLink href={href}>Claim post</ExternalLink>
          ) : null}
        </div>
      </div>
    </div>
  )
}

function ClaimedVictimsPanel({
  victims,
  totalClaims,
}: {
  victims: ClaimedVictim[]
  totalClaims?: number
}) {
  // When the window holds more claims than named victims (unnamed singles +
  // digest-collapsed tallies), reconcile the two counts explicitly so the
  // "N claims / M listed" gap reads as a documented fact, not an inconsistency.
  const listed = victims.length
  const reconcile =
    totalClaims && totalClaims > listed
      ? `${num(listed)} of the ${num(totalClaims)} claims this window named a specific victim.`
      : null
  return (
    <div className="flex flex-col gap-4">
      <p className="text-xs leading-relaxed text-muted">
        Unverified claims republished from the group&rsquo;s own leak site — attributed facts, not a
        SOCDesk verdict. A listing is an allegation by the actor, not a confirmed breach.
        {reconcile ? ` ${reconcile}` : ''}
      </p>
      <div className="flex flex-col divide-y divide-line">
        {victims.map((v) => (
          <VictimRow key={v.id} v={v} />
        ))}
      </div>
    </div>
  )
}

/* ---------------- ATT&CK fingerprint ---------------- */

function MitreFingerprintPanel({
  fingerprint,
  slugSet,
}: {
  fingerprint: NonNullable<ProfileResult['fingerprint']>
  slugSet: Set<string>
}) {
  return (
    <div className="flex flex-col gap-5">
      {fingerprint.description && (
        <p className="text-xs leading-relaxed text-muted">{fingerprint.description}</p>
      )}

      {fingerprint.aliases.length > 0 && (
        <div className="flex flex-col gap-2">
          <SectionLabel>Also tracked as</SectionLabel>
          <AliasChips aliases={fingerprint.aliases} />
        </div>
      )}

      {fingerprint.techniques.length > 0 && (
        <div className="flex flex-col gap-2">
          <SectionLabel>Techniques · {num(fingerprint.techniques.length)}</SectionLabel>
          <div className="flex flex-wrap gap-1.5">
            {fingerprint.techniques.map((t) => (
              <TechniqueChip key={t} id={t} />
            ))}
          </div>
        </div>
      )}

      {fingerprint.software.length > 0 && (
        <div className="flex flex-col gap-2">
          <SectionLabel>
            {fingerprint.kind === 'malware' ? 'Associated groups & tools' : 'Software & malware'} ·{' '}
            {num(fingerprint.software.length)}
          </SectionLabel>
          <div className="flex flex-wrap gap-1.5">
            {fingerprint.software.map((s) => (
              <SoftwareChip key={s} name={s} linkable={slugSet.has(s.toLowerCase())} />
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

/* ---------------- reporting (link-outs) ---------------- */

function ReportingList({ reporting }: { reporting: ProfileResult['reporting'] }) {
  return (
    <div className="flex flex-col divide-y divide-line">
      {reporting.map((r) => {
        const href = safeUrl(r.url)
        return (
          <div key={r.id} className="flex flex-col gap-1.5 py-3 first:pt-0">
            <div className="flex items-center gap-2 font-mono text-micro text-faint">
              <span className="truncate text-muted">{r.outlet}</span>
              <span aria-hidden="true">·</span>
              <span className="whitespace-nowrap">{rel(r.published_at)}</span>
            </div>
            <span className="font-display text-base font-bold tracking-tight text-paper">
              {r.title}
            </span>
            {r.summary && <p className="text-xs leading-relaxed text-muted">{r.summary}</p>}
            {href && <ExternalLink href={href}>Read at {r.outlet}</ExternalLink>}
          </div>
        )
      })}
    </div>
  )
}

/* ---------------- associated malware (right rail) ---------------- */

function AssociatedMalware({ names, slugSet }: { names: string[]; slugSet: Set<string> }) {
  return (
    <div className="flex flex-col gap-2">
      <p className="text-xs leading-relaxed text-muted">
        Families observed alongside this group in ATT&amp;CK and the feed — a co-occurrence surface,
        not a &ldquo;uses&rdquo; assertion.
      </p>
      <div className="flex flex-wrap gap-1.5">
        {names.map((n) => (
          <SoftwareChip key={n} name={n} linkable={slugSet.has(n.toLowerCase())} />
        ))}
      </div>
    </div>
  )
}

/* ---------------- related (MITRE + feed co-occurrence) ---------------- */

function RelatedPanel({ related }: { related: ProfileResult['related'] }) {
  if (!related.length) {
    return (
      <PanelEmpty>
        No related entities recorded — no ATT&amp;CK links or feed co-occurrences in this snapshot.
      </PanelEmpty>
    )
  }
  return (
    <div className="flex flex-col divide-y divide-line">
      {related.map(({ node, edge }) => {
        const pivotable = PIVOTABLE.has(node.type)
        return (
          <div key={node.id} className="flex items-center justify-between gap-3 py-2">
            <span className="flex min-w-0 items-center gap-2">
              <MonoTag tone="faint">{node.type}</MonoTag>
              {pivotable ? (
                <ActorLink
                  name={node.name}
                  className="truncate text-xs font-semibold text-paper hover:text-accent hover:underline"
                >
                  {node.name}
                </ActorLink>
              ) : node.type === 'technique' ? (
                <a
                  href={techniqueUrl(node.name)}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="truncate text-xs text-accent underline-offset-2 hover:underline"
                >
                  {node.name} ↗
                </a>
              ) : (
                <span className="truncate text-xs text-muted">{node.name}</span>
              )}
            </span>
            <span className="whitespace-nowrap font-mono text-micro text-faint">
              {provenance(edge.evidence)} · w{edge.weight}
            </span>
          </div>
        )
      })}
    </div>
  )
}

/* ---------------- the card ---------------- */

export function ActorProfile({
  profile,
  slugSet,
}: {
  profile: ProfileResult
  slugSet: Set<string>
}) {
  const { fingerprint, ransomware, reporting, intel, activity, claimedVictims, associatedMalware } =
    profile

  // A ransomware-live full-profile link-out for an active group (a plain link,
  // not embedded editorial — R3). Memoised only to keep the render tidy.
  const ransomLiveHref = useMemo(
    () =>
      ransomware
        ? `https://www.ransomware.live/group/${encodeURIComponent(profile.slug)}`
        : '',
    [ransomware, profile.slug],
  )

  const nothingOnFile =
    !activity && !intel && !fingerprint && !reporting.length && !claimedVictims.length

  return (
    <div className="flex flex-col gap-6">
      <IdentityHeader profile={profile} />

      {/* items-start keeps each column content-height, so the panels inherit
          BoardPanel's h-full harmlessly (a stretched column would force two
          full-height panels to overlap). */}
      <div className="grid gap-5 lg:grid-cols-[1fr_340px] lg:items-start">
        <div className="flex flex-col gap-5">
          {/* initial access & detection (public-domain intel seed) — the flagship, and
              the most triage-actionable read (CVEs to check, tooling to
              hunt), so it leads when present */}
          {intel && (
            <BoardPanel eyebrow="Initial access & detection" accent>
              <IntelPanel intel={intel} />
            </BoardPanel>
          )}

          {/* leak-site activity — the "who now" read */}
          {activity && (
            <BoardPanel eyebrow="Leak-site activity">
              <ActivityPanel activity={activity} />
            </BoardPanel>
          )}

          {/* claimed victims — the attributed leak-site ledger */}
          {claimedVictims.length > 0 ? (
            <BoardPanel
              eyebrow="Claimed victims"
              aside={<MicroLabel tone="faint">{num(claimedVictims.length)} listed</MicroLabel>}
              footer={
                ransomLiveHref ? (
                  <ExternalLink href={ransomLiveHref}>Full profile at ransomware.live</ExternalLink>
                ) : undefined
              }
            >
              <ClaimedVictimsPanel victims={claimedVictims} totalClaims={ransomware?.totalClaims} />
            </BoardPanel>
          ) : ransomware ? (
            <BoardPanel eyebrow="Claimed victims">
              <PanelEmpty>
                Only rolled-up digest claims this window — no individually-named victim posts to
                list.
              </PanelEmpty>
            </BoardPanel>
          ) : null}

          {/* ATT&CK fingerprint */}
          {fingerprint && (
            <BoardPanel eyebrow="ATT&CK fingerprint">
              <MitreFingerprintPanel fingerprint={fingerprint} slugSet={slugSet} />
            </BoardPanel>
          )}

          {/* reporting */}
          {reporting.length > 0 && (
            <BoardPanel eyebrow="Reporting">
              <ReportingList reporting={reporting} />
            </BoardPanel>
          )}

          {nothingOnFile && (
            <BoardPanel eyebrow="Profile">
              <PanelEmpty>
                No fingerprint, leak-site activity, seeded intel, or reporting names this entity in
                the current snapshot — only graph relations are on file.
              </PanelEmpty>
            </BoardPanel>
          )}
        </div>

        {/* right rail */}
        <div className="flex flex-col gap-5 lg:sticky lg:top-20 lg:self-start">
          <BoardPanel eyebrow="Related entities">
            <RelatedPanel related={profile.related} />
          </BoardPanel>

          {associatedMalware.length > 0 && (
            <BoardPanel eyebrow="Associated malware">
              <AssociatedMalware names={associatedMalware} slugSet={slugSet} />
            </BoardPanel>
          )}
        </div>
      </div>
    </div>
  )
}
