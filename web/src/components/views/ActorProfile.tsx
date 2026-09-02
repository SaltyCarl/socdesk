import { useMemo } from 'react'
import { cx } from '@socdesk/shared/lib/cx'
import { MicroLabel } from '../ui'
import { MonoTag } from './Badges'
import { rel, safeUrl, num } from './format'
import { intelSource, isVendorSourced, vendorLabel } from './intelSource'
import { ExternalLink } from './ExternalLink'
import { VictimLogo } from './VictimLogo'
import { PIVOTABLE, provenance, techniqueUrl } from './relations'
import { ActorLink, BoardPanel, CveLink, PanelEmpty } from '../overview/board-ui'
import { barWidthClass } from '../overview/widths'
import { busiestDay } from './profiles'
import type { DayBucket, ProfileResult, RankedCount } from './profiles'
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

function TechniqueChip({ id, name }: { id: string; name?: string }) {
  return (
    <a
      href={techniqueUrl(id)}
      target="_blank"
      rel="noopener noreferrer"
      title={name ? `${id} · ${name}` : id}
      className="inline-flex items-center gap-1.5 rounded-sm border border-line bg-panel-soft px-1.5 py-0.5 transition-colors duration-150 ease-brand hover:border-line-bright"
    >
      <span className="font-mono text-micro font-semibold text-accent-dim">{id}</span>
      {name && <span className="text-micro text-muted">{name}</span>}
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
      {profile.intel &&
        (isVendorSourced(profile.intel) ? (
          <MonoTag tone="accent">Vendor-reported</MonoTag>
        ) : (
          <MonoTag tone="accent">{intelSource(profile.intel.advisory?.url).org} seeded</MonoTag>
        ))}
      {/* One consistent "ATT&CK <id>" treatment regardless of actor vs. malware
          kind — the metadata rail below no longer repeats it (dedupe). */}
      {fp?.attack_id && <MonoTag tone="muted">ATT&amp;CK {fp.attack_id}</MonoTag>}
      {isApt && <MonoTag tone="muted">APT · reported</MonoTag>}
    </div>
  )
}

/** The identity block: classification badges (incl. the single ATT&CK-id
 *  treatment), aliases, the ATT&CK deep-link, and a rail of status FACTS —
 *  each stated ONLY when known, never synthesised: an absent seed flag renders
 *  nothing (a "RaaS · No" for a seed that merely omitted the flag was a
 *  falsehood, not a fact). The whole rail hides when no fact is known — a
 *  bare divider band is chrome without content. The actor's NAME itself is
 *  not repeated here — it is the page H1 immediately above this card. */
function IdentityHeader({ profile }: { profile: ProfileResult }) {
  const { fingerprint, intel, activity } = profile
  const attackHref = safeUrl(fingerprint?.attackUrl)
  const aliases = fingerprint?.aliases ?? intel?.aliases ?? []
  // raas is tri-state: true / explicit false (both known, both stated) /
  // absent (unknown — say nothing). The seed carries real explicit-false
  // entries (Clop), so the "No" path is live, not speculative.
  const raasKnown = typeof intel?.raas === 'boolean'
  // Cadence facts (claiming groups only) — pure derivations of attributed
  // claim dates, stated only when computable.
  const busiest = activity ? busiestDay(activity.daily) : null
  const hasFacts =
    Boolean(intel?.first_seen) ||
    raasKnown ||
    aliases.length > 0 ||
    Boolean(activity?.lastClaimAt) ||
    busiest !== null

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

      {hasFacts && (
        <div className="flex flex-wrap gap-x-6 gap-y-3 border-t border-line pt-4">
          {intel?.first_seen && <Fact label="First seen">{intel.first_seen}</Fact>}
          {raasKnown && (
            <Fact label="RaaS">{intel!.raas ? 'Yes · affiliate model' : 'No'}</Fact>
          )}
          {activity?.lastClaimAt && <Fact label="Last claim">{rel(activity.lastClaimAt)}</Fact>}
          {busiest && (
            <Fact label="Busiest day">
              {dayLabel(busiest.date)} ({num(busiest.count)})
            </Fact>
          )}
          {aliases.length > 0 && <Fact label="Aliases">{num(aliases.length)}</Fact>}
        </div>
      )}
    </header>
  )
}

/* ---------------- leak-site activity (heat strip + geography) --------------- */

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']

/** ISO `YYYY-MM-DD` → terse `Mon D`, from the string parts only (deterministic,
 *  no Date/locale — the daily buckets are already UTC date keys). */
function dayLabel(iso: string): string {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(iso)
  if (!m) return iso
  return `${MONTHS[Number(m[2]) - 1] ?? m[2]} ${Number(m[3])}`
}

/** Literal Tailwind opacity classes for the heat ladder (JIT can't see a
 *  computed string — the widths.ts trap). Floor 30%: a fainter periwinkle is
 *  near-invisible on the light theme's panel; lit cells also carry a border
 *  so a single-claim day still reads. Note: this quartile ladder deliberately
 *  supersedes the retired weekly chart's one-accent-tone rule — a heat strip
 *  IS its opacity ramp; the tone is still the single volume accent. */
function heatClass(count: number, max: number): string {
  if (count <= 0) return 'bg-panel-soft'
  const q = count / Math.max(1, max)
  const o = q > 0.75 ? 'opacity-100' : q > 0.5 ? 'opacity-75' : q > 0.25 ? 'opacity-50' : 'opacity-30'
  return `border border-line bg-accent ${o}`
}

/** 31-day daily claim heat strip — always renders when the group has ≥1 claim
 *  in the window (the retired weekly chart refused to draw under 2 distinct
 *  weeks, which was most claiming groups). Digest tallies distribute by their
 *  carried per-claim dates (profiles.ts::dailyClaimsFor). Static, no SVG lib;
 *  cell titles are hover-only (touch-inert) so the cells are aria-hidden and
 *  the container carries the summary sentence. */
function HeatStrip({ daily }: { daily: DayBucket[] }) {
  const max = Math.max(1, ...daily.map((d) => d.count))
  const total = daily.reduce((s, d) => s + d.count, 0)
  const peak = daily.reduce((a, b) => (b.count >= a.count ? b : a), daily[0])
  return (
    <div className="flex flex-col gap-1.5">
      <div
        role="img"
        aria-label={`Daily claim volume, ${dayLabel(daily[0].date)} to ${dayLabel(daily[daily.length - 1].date)}: ${total} claims, peaking at ${peak.count} on ${dayLabel(peak.date)}.`}
        className="grid grid-cols-[repeat(31,minmax(0,1fr))] gap-0.5"
      >
        {daily.map((d) => (
          <div
            key={d.date}
            aria-hidden="true"
            title={`${dayLabel(d.date)} · ${d.count} claim${d.count === 1 ? '' : 's'}`}
            className={cx('h-6 rounded-[2px]', heatClass(d.count, max))}
          />
        ))}
      </div>
      <div className="flex items-center justify-between font-mono text-micro text-faint">
        <span>{dayLabel(daily[0].date)}</span>
        <span className="text-accent">peak {num(peak.count)}</span>
        <span>{dayLabel(daily[daily.length - 1].date)}</span>
      </div>
    </div>
  )
}

/** Guarded region-name lookup: only a clean 2-letter code goes to
 *  Intl.DisplayNames (upstream emits junk + 3-letter codes); anything else —
 *  or a lookup throw — falls back to the raw label. Text, never emoji flags
 *  (Windows renders regional indicators as letter pairs). */
function countryLabel(code: string): string {
  if (!/^[A-Za-z]{2}$/.test(code)) return code
  try {
    const name = new Intl.DisplayNames(['en'], { type: 'region' }).of(code.toUpperCase())
    return name && name !== code.toUpperCase() ? `${code.toUpperCase()} · ${name}` : code
  } catch {
    return code
  }
}

/** Ranked label · count · volume-bar rows (the ISP-leaderboard idiom). */
function RankedBars({ rows, format }: { rows: RankedCount[]; format?: (label: string) => string }) {
  const max = Math.max(1, ...rows.map((r) => r.count))
  return (
    <div className="flex flex-col gap-1.5">
      {rows.map((r) => (
        <div key={r.label} className="flex items-center gap-3">
          <span className="w-40 shrink-0 truncate text-xs text-paper">
            {(format ?? ((l: string) => l))(r.label)}
          </span>
          <span className="h-1.5 flex-1 overflow-hidden rounded-full bg-panel-soft">
            <span className={cx('block h-full rounded-full bg-accent', barWidthClass(r.count / max))} />
          </span>
          <span className="w-8 shrink-0 text-right font-mono text-xs tabular-nums text-paper">
            {num(r.count)}
          </span>
        </div>
      ))}
    </div>
  )
}

function ActivityPanel({ activity }: { activity: NonNullable<ProfileResult['activity']> }) {
  // Sectors seen only via digests (distinct coverage, no per-claim count) —
  // rendered as plain chips under the counted bars so digest coverage isn't
  // silently dropped while counts stay honest (singles only).
  const counted = new Set(activity.sectorCounts.map((r) => r.label))
  const digestOnlySectors = activity.sectors.filter((s) => !counted.has(s))
  return (
    <div className="flex flex-col gap-5">
      <div className="flex items-end justify-between gap-4">
        <div className="flex flex-col gap-1">
          <SectionLabel>Victim claims · window</SectionLabel>
          <span className="font-display text-2xl font-extrabold tabular-nums text-paper">
            {num(activity.victimCount)}
          </span>
        </div>
        <span className="font-mono text-micro text-faint">last 31 days</span>
      </div>

      {activity.daily.length > 0 && <HeatStrip daily={activity.daily} />}
      {activity.hasLegacyDigest && (
        <p className="text-micro text-faint">
          One or more rolled-up digests carry no per-claim dates — their tallies land on the
          digest&rsquo;s own day.
        </p>
      )}

      <div className="flex flex-col gap-2">
        <SectionLabel>Target sectors</SectionLabel>
        {activity.sectorCounts.length > 0 ? (
          <RankedBars rows={activity.sectorCounts} />
        ) : activity.sectors.length === 0 ? (
          <p className="text-xs text-muted">None attributed by the source.</p>
        ) : null}
        {digestOnlySectors.length > 0 && (
          <div className="flex flex-wrap gap-1.5">
            {digestOnlySectors.map((s) => (
              <MonoTag key={s} tone="ghost">
                {s}
              </MonoTag>
            ))}
          </div>
        )}
        {activity.hasDigest && (
          <p className="text-micro text-faint">
            Counts cover individually-posted claims only — rolled-up digests list sectors without
            per-claim counts.
          </p>
        )}
      </div>

      <div className="flex flex-col gap-2">
        <SectionLabel>Target countries</SectionLabel>
        {activity.countryCounts.length > 0 ? (
          <RankedBars rows={activity.countryCounts} format={countryLabel} />
        ) : (
          <p className="text-xs text-muted">None attributed by the source.</p>
        )}
        {activity.hasDigest && (
          <p className="text-micro text-faint">
            Partial — rolled-up digest claims omit country, so more may be affected.
          </p>
        )}
      </div>
    </div>
  )
}

/* ---------------- initial access & detection (curated public-domain intel seed) --- */

/** The vendor-tier attribution line — the render-critical divergence from the
 *  gov panel above it: no "seeded"/advisory language, an explicit
 *  unverified/non-government framing, and the cited vendor names linked
 *  inline from `sources[]`. This sentence is SOCDesk's own words describing
 *  the facts below; the facts themselves are atomic values (a CVE id, a
 *  tool name, …), never the vendor's prose. */
function VendorAttribution({ sources }: { sources: { id: string; url: string }[] }) {
  return (
    <p className="text-xs leading-relaxed text-muted">
      Atomic facts compiled from public vendor threat-reporting — unverified by SOCDesk, not a
      government advisory. Sources:{' '}
      {sources.map((s, i) => {
        const href = safeUrl(s.url)
        return (
          <span key={s.id}>
            {href ? <ExternalLink href={href}>{vendorLabel(s.id)}</ExternalLink> : vendorLabel(s.id)}
            {i < sources.length - 1 ? ', ' : '.'}
          </span>
        )
      })}
    </p>
  )
}

/** Curated triage block. TWO distinct provenance tiers share this one panel
 *  shape, discriminated by `isVendorSourced` (no `advisory` field means
 *  vendor-tier — see intelSource.ts):
 *
 *  - GOV tier: sourced from a public-domain US federal advisory (CISA
 *    #StopRansomware or HHS HC3, per the schema's host gate — both 17
 *    U.S.C. §105 public domain). The attributing org and document type are
 *    derived from `intel.advisory.url`'s host (`intelSource`) — never
 *    hardcoded to a single publisher. Carries the advisory link-out, the
 *    (public-domain-only) note-image figure, and the "<org> seed" footer.
 *  - VENDOR tier: NO advisory at all — instead `sources[]` cites one or more
 *    reputable vendor threat-reports. Framed by `VendorAttribution` above,
 *    NEVER the gov "seeded"/advisory treatment, and NEVER a note-image
 *    branch (vendor figures are not public domain — the data model omits
 *    `note_image` for these entries, and `figureHref` below is force-empty
 *    as defense in depth against a future data-entry mistake).
 *
 *  In both tiers, initial-access CVEs (pivot into our lookup), tools (hunt
 *  pivots), and on-host signatures render identically — every fact
 *  attributed to its source, nothing synthesised, honest-empty per field.
 *  Absent entirely when the group is unseeded. */
function IntelPanel({ intel }: { intel: RansomIntel }) {
  const vendor = isVendorSourced(intel)
  const cves = intel.initial_access_cves ?? []
  const tools = intel.tools ?? []
  const notes = intel.ransom_note ?? []
  const exts = intel.extensions ?? []
  const sources = intel.sources ?? []
  const advisoryHref = safeUrl(intel.advisory?.url)
  // Vendor entries never carry note_image (vendor figures aren't
  // public-domain) — force-empty here so a future data-entry mistake can't
  // resurrect the gov figure treatment for a vendor-sourced group.
  const figureHref = vendor ? '' : safeUrl(intel.note_image)
  const source = intelSource(intel.advisory?.url ?? intel.note_image)
  const figureHost = figureHref ? new URL(figureHref).hostname : ''
  return (
    <div className="flex flex-col gap-5">
      {vendor ? (
        <VendorAttribution sources={sources} />
      ) : (
        <p className="text-xs leading-relaxed text-muted">
          Initial access, tooling and detection signals below are drawn from the group&rsquo;s{' '}
          {source.product} — attributed facts, not a SOCDesk assessment.
        </p>
      )}

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

      {/* Vendor tier: sources are already linked inline in VendorAttribution
          above — the footer here is just the (honest, optional) reviewed
          date, never a duplicate "seed"/org line (that language is gov-only
          — see isVendorSourced). Gov tier: unchanged "<org> seed" footer +
          its own sources list. */}
      {vendor
        ? intel.last_reviewed && (
            <p className="border-t border-line pt-3 font-mono text-micro text-faint">
              reviewed {intel.last_reviewed}
            </p>
          )
        : (intel.last_reviewed || intel.advisory_date || sources.length > 0) && (
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
  techniqueNames,
}: {
  fingerprint: NonNullable<ProfileResult['fingerprint']>
  slugSet: Set<string>
  techniqueNames?: Record<string, string>
}) {
  return (
    <div className="flex flex-col gap-5">
      {fingerprint.description && (
        <p className="text-xs leading-relaxed text-muted">{fingerprint.description}</p>
      )}

      {/* Aliases render ONCE — the IdentityHeader chips are the canonical spot
          (an "Also tracked as" block here was the same array a third time). */}
      {fingerprint.techniques.length > 0 && (
        <div className="flex flex-col gap-2">
          <SectionLabel>Techniques · {num(fingerprint.techniques.length)}</SectionLabel>
          <div className="flex flex-wrap gap-1.5">
            {fingerprint.techniques.map((t) => (
              <TechniqueChip key={t} id={t} name={techniqueNames?.[t]} />
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
        Families co-occurring with this group in feed reporting, beyond its ATT&amp;CK software
        list — a co-occurrence surface, not a &ldquo;uses&rdquo; assertion.
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
  techniqueNames,
}: {
  profile: ProfileResult
  slugSet: Set<string>
  techniqueNames?: Record<string, string>
}) {
  const { fingerprint, ransomware, reporting, intel, activity, claimedVictims, associatedMalware } =
    profile

  // The fusion UNIONS fingerprint.software into associatedMalware, so on an
  // actor page the same names rendered twice (fingerprint "Software & malware"
  // AND this rail). Keep the rail for what its copy actually promises — feed
  // co-occurrence BEYOND ATT&CK — by filtering the fingerprint names out here,
  // and gate the panel on the FILTERED list (an intro sentence over zero chips
  // is not an honest empty). No-op on malware pages (their software is []).
  const fingerprintSoftware = useMemo(
    () => new Set((fingerprint?.software ?? []).map((s) => s.toLowerCase())),
    [fingerprint],
  )
  const feedOnlyMalware = useMemo(
    () => associatedMalware.filter((n) => !fingerprintSoftware.has(n.toLowerCase())),
    [associatedMalware, fingerprintSoftware],
  )

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
            <BoardPanel
              eyebrow={isVendorSourced(intel) ? 'Reported TTPs' : 'Initial access & detection'}
              accent
            >
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
              <MitreFingerprintPanel
                fingerprint={fingerprint}
                slugSet={slugSet}
                techniqueNames={techniqueNames}
              />
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

          {feedOnlyMalware.length > 0 && (
            <BoardPanel eyebrow="Associated malware">
              <AssociatedMalware names={feedOnlyMalware} slugSet={slugSet} />
            </BoardPanel>
          )}
        </div>
      </div>
    </div>
  )
}
