import { useMemo, useState } from 'react'
import { cx } from '@socdesk/shared/lib/cx'
import { MicroLabel } from '../ui'
import { KevBadge, MonoTag } from './Badges'
import { pct, rel, safeUrl, num } from './format'
import { intelSource, isVendorSourced, vendorLabel } from './intelSource'
import { ExternalLink } from './ExternalLink'
import { VictimLogo } from './VictimLogo'
import { PIVOTABLE, provenance, relatedMinusUsedBy, techniqueUrl } from './relations'
import { ActorLink, BoardPanel, CveLink, PanelEmpty } from '../overview/board-ui'
import { barWidthClass } from '../overview/widths'
import { busiestDay } from './profiles'
import { distinctiveSplit } from './derived'
import { attackDetectionUrl, sigmaSearchUrl } from './huntpack'
import { TechniqueChip } from './TechniqueChip'
import { HeatStrip } from './HeatStrip'
import { dayLabel } from './activity-ui'
import { SynthesisBand } from './SynthesisBand'
import { ProfileNav } from './ProfileNav'
import { navSections, useProfileNav } from './useProfileNav'
import type { HuntPack, HuntRow } from './huntpack'
import type { OverlapRow } from './derived'
import type { ProfileResult, RankedCount } from './profiles'
import type { ClaimedVictim, CveContext, RansomIntel, TechniqueTacticsPayload } from './types'

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
function IntelPanel({
  intel,
  cveContext,
  toolCounts,
  seedCount = 0,
}: {
  intel: RansomIntel
  /** Publish-time KEV/EPSS join (ransomware_intel.json cve_context). */
  cveContext?: Record<string, CveContext>
  /** How many seeded crews list each tool (derived.ts::seededToolCounts). */
  toolCounts?: Map<string, number>
  seedCount?: number
}) {
  const vendor = isVendorSourced(intel)
  const rawCves = intel.initial_access_cves ?? []
  // Priority order: EPSS desc (the only real discriminator — every current
  // seed CVE is KEV-listed), unknowns last, id tiebreak. NO overdue boolean:
  // the lookup doctrine (lookupModel.ts) pins that nearly every KEV entry is
  // past due, so a boolean flags ~everything and reads as wallpaper.
  const cves = [...rawCves].sort((a, b) => {
    const ea = cveContext?.[a]?.epss ?? -1
    const eb = cveContext?.[b]?.epss ?? -1
    return eb - ea || a.localeCompare(b)
  })
  const kevCount = cves.filter((c) => cveContext?.[c]?.kev).length
  const allKev = cves.length > 0 && kevCount === cves.length
  // The "no mark = not in KEV/NVD" caveat is only TRUE once the join actually
  // ran — pre-refresh (no cve_context at all) absence means "unjoined", and
  // stating otherwise would itself be a falsehood.
  const someUnmarked = cveContext != null && cves.some((c) => !cveContext[c])
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
          {allKev && (
            <p className="text-micro text-faint">
              All {num(cves.length)} are in CISA&rsquo;s KEV catalog — actively exploited in the
              wild. Ordered by EPSS exploitation probability.
            </p>
          )}
          <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1.5">
            {cves.map((c) => {
              const ctx = cveContext?.[c]
              return (
                <span key={c} className="inline-flex items-center gap-1">
                  <CveLink cve={c} />
                  {/* only mark KEV per-chip in a MIXED panel — when everything
                      is KEV (today's reality) the panel line above carries it */}
                  {!allKev && ctx?.kev && <KevBadge ransomware={ctx.kev_ransomware} />}
                  {ctx?.epss != null && (
                    <span
                      title={`EPSS ${pct(ctx.epss)} — probability of exploitation activity (FIRST)`}
                      className="font-mono text-micro tabular-nums text-faint"
                    >
                      {pct(ctx.epss)}
                    </span>
                  )}
                  {allKev && ctx?.kev_ransomware && (
                    <span
                      title="known ransomware campaign use (CISA KEV)"
                      className="font-mono text-micro font-semibold text-faint"
                    >
                      R
                    </span>
                  )}
                </span>
              )
            })}
          </div>
          <p className="text-micro text-faint">
            Check whether these are exposed on the affected customer.
            {someUnmarked &&
              ' A CVE without a mark isn’t in the KEV catalog or the current NVD window.'}
          </p>
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
            {tools.map((t) => {
              // Shared-tradecraft context: a count over the curated seed,
              // stated with its denominator — never a "commodity" verdict.
              const n = toolCounts?.get(t.toLowerCase()) ?? 0
              const shared = n >= 2 && seedCount > 0
              return (
                <MonoTag
                  key={t}
                  tone="ghost"
                  title={shared ? `listed by ${num(n)} of ${num(seedCount)} seeded crews` : undefined}
                >
                  {t}
                  {shared && <span className="text-faint"> · {num(n)}/{num(seedCount)}</span>}
                </MonoTag>
              )
            })}
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

/** Tactic-grouped technique matrix: stacked labeled sections in the BUNDLE'S
 *  own kill-chain order (never a hardcoded tactic list — the vocabulary
 *  drifts), chips wrapping within each — same semantic as a Navigator layer,
 *  zero horizontal scroll. A multi-tactic technique renders under EACH of its
 *  tactics (ATT&CK's own semantic); the honesty line states the fan-out.
 *  Techniques with no catalog entry (or an unknown phase) land in an appended
 *  "Other" bucket — never dropped. */
function TacticMatrix({
  techniques,
  catalog,
  techniqueNames,
  distinctiveSet,
  hintFor,
}: {
  techniques: string[]
  catalog: TechniqueTacticsPayload
  techniqueNames?: Record<string, string>
  distinctiveSet: Set<string>
  hintFor: (t: string) => string | undefined
}) {
  const known = new Map(catalog.order.map((o) => [o.slug, o.name]))
  const buckets = new Map<string, string[]>()
  for (const t of techniques) {
    const phases = (catalog.tactics[t] ?? []).filter((p) => known.has(p))
    const targets = phases.length ? phases : ['other']
    for (const p of targets) {
      const arr = buckets.get(p) ?? []
      arr.push(t)
      buckets.set(p, arr)
    }
  }
  const sections = [
    ...catalog.order.filter((o) => buckets.has(o.slug)),
    ...(buckets.has('other') ? [{ slug: 'other', name: 'Other' }] : []),
  ]
  const cells = [...buckets.values()].reduce((s, a) => s + a.length, 0)
  return (
    <div className="flex flex-col gap-4">
      {cells > techniques.length && (
        <p className="text-micro text-faint">
          {num(techniques.length)} techniques · {num(cells)} cells across {num(sections.length)}{' '}
          tactics (a multi-tactic technique appears under each of its tactics).
        </p>
      )}
      {sections.map((s) => {
        const ids = buckets.get(s.slug)!
        return (
          <div key={s.slug} className="flex flex-col gap-1.5">
            <SectionLabel>
              {s.name} · {num(ids.length)}
            </SectionLabel>
            <div className="flex flex-wrap gap-1.5">
              {ids.map((t) => (
                <TechniqueChip
                  key={`${s.slug}:${t}`}
                  id={t}
                  name={techniqueNames?.[t]}
                  hint={hintFor(t)}
                  distinctive={distinctiveSet.has(t)}
                />
              ))}
            </div>
          </div>
        )
      })}
    </div>
  )
}

function MitreFingerprintPanel({
  fingerprint,
  slugSet,
  techniqueNames,
  prevalence,
  actorCount = 0,
  tacticsCatalog,
}: {
  fingerprint: NonNullable<ProfileResult['fingerprint']>
  slugSet: Set<string>
  techniqueNames?: Record<string, string>
  /** Snapshot technique prevalence (id → tracked groups using it) — drives
   *  the distinctive/common split. Absent → the plain flat wall. */
  prevalence?: Map<string, number>
  actorCount?: number
  /** technique_tactics.json — present ⇒ the tactic-grouped matrix layout;
   *  absent/loading ⇒ the distinctive/common (or flat) chip layout, so
   *  pre-refresh deploys degrade cleanly. */
  tacticsCatalog?: TechniqueTacticsPayload
}) {
  // Rarity split: distinctive (≤3 tracked groups in this snapshot) leads;
  // the commodity tail collapses. 42% of actors have ZERO distinctive
  // techniques — they keep today's flat wall rather than an empty header
  // over an everything-collapsed page.
  const split = prevalence ? distinctiveSplit(fingerprint.techniques, prevalence) : null
  const useSplit = split !== null && split.distinctive.length > 0
  const distinctiveSet = new Set(split?.distinctive ?? [])
  const useMatrix =
    tacticsCatalog != null && tacticsCatalog.order.length > 0 && fingerprint.techniques.length > 0
  const hintFor = (t: string): string | undefined => {
    const p = prevalence?.get(t)
    return p ? `used by ${num(p)} of ${num(actorCount)} tracked groups in this snapshot` : undefined
  }
  return (
    <div className="flex flex-col gap-5">
      {fingerprint.description && (
        <p className="text-xs leading-relaxed text-muted">{fingerprint.description}</p>
      )}

      {/* Aliases render ONCE — the IdentityHeader chips are the canonical spot
          (an "Also tracked as" block here was the same array a third time). */}
      {useMatrix && (
        <TacticMatrix
          techniques={fingerprint.techniques}
          catalog={tacticsCatalog!}
          techniqueNames={techniqueNames}
          distinctiveSet={distinctiveSet}
          hintFor={hintFor}
        />
      )}

      {!useMatrix &&
        fingerprint.techniques.length > 0 &&
        (useSplit ? (
          <>
            <div className="flex flex-col gap-2">
              <SectionLabel accent>
                Distinctive techniques · {num(split.distinctive.length)}
              </SectionLabel>
              <p className="text-micro text-faint">
                Listed by ≤3 of the {num(actorCount)} tracked groups in this snapshot — what
                makes this fingerprint unusual. A derived count over ATT&amp;CK data, not an
                exclusivity claim.
              </p>
              <div className="flex flex-wrap gap-1.5">
                {split.distinctive.map((t) => (
                  <TechniqueChip
                    key={t}
                    id={t}
                    name={techniqueNames?.[t]}
                    hint={hintFor(t)}
                    distinctive
                  />
                ))}
              </div>
            </div>
            <details className="flex flex-col gap-2">
              <summary className="cursor-pointer select-none font-mono text-micro font-semibold uppercase tracking-label text-faint">
                Common techniques · {num(split.common.length)}
              </summary>
              <div className="mt-2 flex flex-wrap gap-1.5">
                {split.common.map((t) => (
                  <TechniqueChip key={t} id={t} name={techniqueNames?.[t]} hint={hintFor(t)} />
                ))}
              </div>
            </details>
          </>
        ) : (
          <div className="flex flex-col gap-2">
            <SectionLabel>Techniques · {num(fingerprint.techniques.length)}</SectionLabel>
            <div className="flex flex-wrap gap-1.5">
              {fingerprint.techniques.map((t) => (
                <TechniqueChip key={t} id={t} name={techniqueNames?.[t]} hint={hintFor(t)} />
              ))}
            </div>
          </div>
        ))}

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

/* ---------------- hunt pack (validated hunting queries) ---------------- */

/** Truth-returning clipboard write — this project has shipped a button that
 *  claimed success while the clipboard silently rejected the write
 *  (shared/verdict-cards/copy.ts lesson); never claim what didn't happen. */
async function copyPlain(text: string): Promise<boolean> {
  try {
    if (!navigator.clipboard?.writeText) return false
    await navigator.clipboard.writeText(text)
    return true
  } catch {
    return false
  }
}

function CopyKqlButton({ kql }: { kql: string }) {
  const [state, setState] = useState<'idle' | 'copied' | 'blocked'>('idle')
  const label = state === 'copied' ? 'Copied' : state === 'blocked' ? 'Clipboard blocked' : 'Copy KQL'
  return (
    <button
      type="button"
      onClick={() => {
        void copyPlain(kql).then((ok) => {
          setState(ok ? 'copied' : 'blocked')
          setTimeout(() => setState('idle'), 2000)
        })
      }}
      className="inline-flex items-center rounded-md border border-line bg-panel px-2.5 py-1 font-mono text-micro font-semibold text-muted transition-colors duration-150 ease-brand hover:border-line-bright hover:text-paper focus-visible:outline-2 focus-visible:outline-accent"
    >
      {label}
    </button>
  )
}

const DIALECT_CAVEAT: Record<string, string> = {
  log_analytics:
    'Written for a Sentinel workspace (TimeGenerated); in Defender advanced hunting swap TimeGenerated → Timestamp and re-validate.',
  advanced_hunting:
    'Written for Defender advanced hunting (Timestamp); in a Sentinel workspace swap Timestamp → TimeGenerated and re-validate.',
}

function HuntRowView({ row, techniqueNames }: { row: HuntRow; techniqueNames?: Record<string, string> }) {
  const r = row.rule
  const href = safeUrl(r.source.url)
  const kindLabel =
    r.source.kind === 'sentinel' ? 'Microsoft Sentinel community' : r.source.kind === 'sigma' ? 'SigmaHQ' : 'SOCDesk'
  const provenance = [
    kindLabel,
    // drop a redundant author that just repeats the kind label (SOCDesk's own rules)
    r.source.author && r.source.author !== kindLabel ? r.source.author : undefined,
    r.source.license === 'DRL' ? 'DRL 1.1' : r.source.license,
    r.source.modified ? `modified ${r.source.modified}` : undefined,
    r.tested ? `tested ${r.tested}` : undefined,
  ].filter(Boolean).join(' · ')
  return (
    <div className="flex flex-col gap-2 border-b border-line py-3 first:pt-0 last:border-0 last:pb-0">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-sm font-semibold text-paper">{r.title}</span>
        <MonoTag tone="ghost">{r.dialect === 'log_analytics' ? 'Sentinel LA' : 'Adv. hunting'}</MonoTag>
      </div>
      <div className="flex flex-wrap gap-1.5">
        {row.matched.map((t) => (
          <TechniqueChip key={t} id={t} name={techniqueNames?.[t]} />
        ))}
      </div>
      <details>
        <summary className="cursor-pointer select-none font-mono text-micro font-semibold uppercase tracking-label text-accent">
          View KQL
        </summary>
        {/* whitespace-pre + horizontal scroll — wrap/break-all would split KQL
            identifiers mid-token (differs from DecodeLadder on purpose). */}
        <pre className="mt-2 overflow-x-auto whitespace-pre rounded-md border border-line bg-panel p-3 font-mono text-micro text-paper">
          {r.kql}
        </pre>
        <div className="mt-2">
          <CopyKqlButton kql={r.kql} />
        </div>
      </details>
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1 font-mono text-micro text-faint">
        <span>{provenance}</span>
        {href && <ExternalLink href={href}>source</ExternalLink>}
      </div>
    </div>
  )
}

/** The hunt pack: validated hunting queries joined to this profile's
 *  technique fingerprint, kill-chain-ordered. Every row is a community or
 *  SOCDesk-authored query that passed the emulator validation gate —
 *  syntax-validated, NOT a detection guarantee. */
function HuntPackPanel({
  pack,
  techniqueNames,
}: {
  pack: HuntPack
  techniqueNames?: Record<string, string>
}) {
  const dialects = new Set(pack.sections.flatMap((s) => s.rows.map((r) => r.rule.dialect)))
  const hasSigma = pack.sections.some((s) => s.rows.some((r) => r.rule.source.kind === 'sigma'))
  return (
    <div className="flex flex-col gap-4">
      <p className="text-xs leading-relaxed text-muted">
        Community hunting queries matched to this fingerprint, validated for syntax against the
        Kusto emulator — validate table names and thresholds against the customer&rsquo;s schema
        before running. A starting point, not a detection guarantee.
      </p>
      {[...dialects].sort().map((d) => (
        <p key={d} className="text-micro text-faint">
          {DIALECT_CAVEAT[d]}
        </p>
      ))}
      {hasSigma && (
        <p className="text-micro text-faint">
          Sigma-derived rules republished under the{' '}
          <ExternalLink href="https://github.com/SigmaHQ/Detection-Rule-License/blob/main/LICENSE.Detection.Rules.md">
            Detection Rule License
          </ExternalLink>
        </p>
      )}

      {pack.totalMatched === 0 ? (
        <p className="text-xs text-muted" role="status">
          No curated queries match this fingerprint yet — the corpus is young. Upstream detection
          references for each technique are linked below.
        </p>
      ) : (
        pack.sections.map((s) => (
          <div key={s.slug} className="flex flex-col gap-1.5">
            <SectionLabel>
              {s.name} · {num(s.rows.length)}
            </SectionLabel>
            <div className="flex flex-col">
              {s.rows.map((row) => (
                <HuntRowView key={row.rule.id} row={row} techniqueNames={techniqueNames} />
              ))}
            </div>
          </div>
        ))
      )}
      {pack.overflow > 0 && (
        <p className="text-micro text-faint">
          {num(pack.overflow)} further matching queries not shown — the panel caps at 50.
        </p>
      )}

      {pack.uncovered.length > 0 && (
        <details>
          <summary className="cursor-pointer select-none font-mono text-micro font-semibold uppercase tracking-label text-faint">
            {num(pack.uncovered.length)} techniques with no curated query
          </summary>
          <div className="mt-2 flex flex-col gap-1">
            {pack.uncovered.map((t) => (
              <div key={t} className="flex flex-wrap items-center gap-x-2 font-mono text-micro">
                <span className="font-semibold text-accent-dim">{t}</span>
                <span className="text-muted">{techniqueNames?.[t] ?? ''}</span>
                <ExternalLink href={attackDetectionUrl(t)}>ATT&amp;CK detection</ExternalLink>
                <ExternalLink href={sigmaSearchUrl(t)}>SigmaHQ search (GitHub sign-in)</ExternalLink>
              </div>
            ))}
            {pack.preCompromiseOmitted > 0 && (
              <p className="mt-1 text-micro text-faint">
                {num(pack.preCompromiseOmitted)} pre-compromise techniques (reconnaissance /
                resource development) omitted — not host-huntable.
              </p>
            )}
          </div>
        </details>
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

/* ---------------- derived panels (right rail) ---------------- */

/** Top peers by shared ATT&CK techniques — arithmetic over the two actors'
 *  technique lists, labeled as such (never an asserted relationship). */
function SharedTechniqueActors({ rows, selfTotal }: { rows: OverlapRow[]; selfTotal: number }) {
  const max = Math.max(1, ...rows.map((r) => r.shared))
  return (
    <div className="flex flex-col gap-2">
      <p className="text-xs leading-relaxed text-muted">
        Computed from each actor&rsquo;s ATT&amp;CK technique list — a shared count, not an
        asserted relationship.
      </p>
      <div className="flex flex-col gap-1.5">
        {rows.map((r) => (
          <div key={r.slug} className="flex items-center gap-3">
            <ActorLink
              name={r.slug}
              className="w-32 shrink-0 truncate font-mono text-xs font-semibold text-accent-dim hover:text-accent hover:underline"
            >
              {r.name}
            </ActorLink>
            <span className="h-1.5 flex-1 overflow-hidden rounded-full bg-panel-soft">
              <span className={cx('block h-full rounded-full bg-accent', barWidthClass(r.shared / max))} />
            </span>
            <span className="shrink-0 whitespace-nowrap font-mono text-micro tabular-nums text-paper">
              {num(r.shared)} of {num(Math.min(selfTotal, r.total))}
            </span>
          </div>
        ))}
      </div>
    </div>
  )
}

/** The malware reverse index: every tracked group whose ATT&CK fingerprint
 *  lists this family. ATT&CK-derived only (the feed co-occurrence rail keeps
 *  its own separate, explicitly non-"uses" framing). */
function UsedByGroups({
  rows,
  actorCount,
  slugSet,
}: {
  rows: { name: string; slug: string }[]
  actorCount: number
  slugSet: Set<string>
}) {
  return (
    <div className="flex flex-col gap-2">
      <p className="text-xs leading-relaxed text-muted">
        Listed in {num(rows.length)} of the {num(actorCount)} tracked groups&rsquo; ATT&amp;CK
        profiles.
      </p>
      <div className="flex flex-wrap gap-1.5">
        {rows.map((r) =>
          slugSet.has(r.slug) ? (
            <ActorLink key={r.slug} name={r.slug} className={CHIP_LINK}>
              {r.name}
            </ActorLink>
          ) : (
            <span key={r.slug} className={CHIP_PLAIN}>
              {r.name}
            </span>
          ),
        )}
      </div>
    </div>
  )
}

const CHIP_LINK =
  'inline-flex items-center rounded-sm border border-[var(--edge-accent)] bg-[var(--tint-accent)] px-1.5 py-0.5 font-mono text-micro font-semibold text-accent hover:underline'
const CHIP_PLAIN =
  'inline-flex items-center rounded-sm border border-line bg-panel-soft px-1.5 py-0.5 font-mono text-micro text-muted'

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
  sharedActors,
  usedBy,
  prevalence,
  actorCount = 0,
  tacticsCatalog,
  huntPack,
  cveContext,
  toolCounts,
  seedCount = 0,
}: {
  profile: ProfileResult
  slugSet: Set<string>
  techniqueNames?: Record<string, string>
  /** Derived (route-computed): top peers by shared ATT&CK techniques. */
  sharedActors?: OverlapRow[]
  /** Derived (route-computed): groups whose fingerprints list this malware. */
  usedBy?: { name: string; slug: string }[]
  /** Derived (route-computed): snapshot technique prevalence. */
  prevalence?: Map<string, number>
  actorCount?: number
  /** technique_tactics.json — drives the tactic-grouped matrix layout. */
  tacticsCatalog?: TechniqueTacticsPayload
  /** Publish-time KEV/EPSS join for the seed's initial-access CVEs. */
  cveContext?: Record<string, CveContext>
  /** The validated-hunting-query join for this fingerprint (huntpack.ts). */
  huntPack?: HuntPack
  /** Seeded-crew tool counts (derived.ts::seededToolCounts) + denominator. */
  toolCounts?: Map<string, number>
  seedCount?: number
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

  // N2 de-dup (2026-09-03 re-run): on a MALWARE page the "Used by tracked groups"
  // reverse-index is the canonical home for the using-actors, so the same actors
  // in "Related entities" are a redundant second copy. Strip the reverse-index
  // actors out of the related list here; the panel is then gated on the FILTERED
  // list below so an emptied list omits the panel rather than rendering the now
  // FALSE "no related entities recorded" empty (there were ATT&CK links). No-op on
  // actor pages (usedBy is undefined there → the list passes through unchanged).
  const dedupedRelated = useMemo(
    () => (usedBy?.length ? relatedMinusUsedBy(profile.related, usedBy) : profile.related),
    [profile.related, usedBy],
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

  // Jump-nav landmarks (document order, gated on existence). `hasRelated` mirrors
  // the right-rail visibility below — the rail carries the Related-entities panel
  // on every page except a malware page whose reverse-index absorbed all related
  // actors (that page still has the reverse-index, so the rail is non-empty).
  const hasActivity = Boolean(activity)
  const hasFingerprint = Boolean(fingerprint)
  const hasHuntpack = Boolean(fingerprint && huntPack)
  const hasRelated =
    Boolean(sharedActors && sharedActors.length > 0 && fingerprint) ||
    Boolean(fingerprint?.kind === 'malware' && usedBy && usedBy.length > 0) ||
    dedupedRelated.length > 0 ||
    !usedBy?.length ||
    feedOnlyMalware.length > 0
  // Memoise on the primitive flags so useProfileNav re-subscribes only when the
  // set of sections changes (a new array each render would thrash the observer).
  const sections = useMemo(
    () => navSections({ hasActivity, hasFingerprint, hasHuntpack, hasRelated }),
    [hasActivity, hasFingerprint, hasHuntpack, hasRelated],
  )
  const { activeId } = useProfileNav(sections)

  return (
    <div className="flex flex-col gap-6">
      {/* decision layer — identity + the one-screen synthesis, always open */}
      <div id="overview" className="flex scroll-mt-[6.5rem] flex-col gap-6">
        <IdentityHeader profile={profile} />
        <SynthesisBand
          fingerprint={fingerprint}
          prevalence={prevalence}
          actorCount={actorCount}
          huntPack={huntPack}
          activity={activity}
          intel={intel}
          cveContext={cveContext}
          techniqueNames={techniqueNames}
        />
      </div>

      <ProfileNav sections={sections} activeId={activeId} />

      {/* items-start keeps each column content-height, so the panels inherit
          BoardPanel's h-full harmlessly (a stretched column would force two
          full-height panels to overlap). */}
      <div className="grid gap-5 lg:grid-cols-[1fr_340px] lg:items-start">
        <div className="flex flex-col gap-5">
          {/* initial access & detection (public-domain intel seed) — the flagship,
              the most triage-actionable read, kept OPEN in the decision layer */}
          {intel && (
            <BoardPanel
              eyebrow={isVendorSourced(intel) ? 'Reported TTPs' : 'Initial access & detection'}
              accent
            >
              <IntelPanel intel={intel} cveContext={cveContext} toolCounts={toolCounts} seedCount={seedCount} />
            </BoardPanel>
          )}

          {/* leak-site activity — the "who now" read, kept OPEN */}
          {activity && (
            <BoardPanel id="activity" eyebrow="Leak-site activity" className="scroll-mt-[6.5rem]">
              <ActivityPanel activity={activity} />
            </BoardPanel>
          )}

          {/* claimed victims — collapsed reference (attributed leak-site ledger) */}
          {claimedVictims.length > 0 ? (
            <BoardPanel
              id="victims"
              collapsible
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
            <BoardPanel id="victims" collapsible eyebrow="Claimed victims">
              <PanelEmpty>
                Only rolled-up digest claims this window — no individually-named victim posts to
                list.
              </PanelEmpty>
            </BoardPanel>
          ) : null}

          {/* ATT&CK fingerprint — collapsed reference (the full tactic matrix) */}
          {fingerprint && (
            <BoardPanel
              id="fingerprint"
              collapsible
              eyebrow="ATT&CK fingerprint"
              aside={<MicroLabel tone="faint">{num(fingerprint.techniques.length)} techniques</MicroLabel>}
            >
              <MitreFingerprintPanel
                fingerprint={fingerprint}
                slugSet={slugSet}
                techniqueNames={techniqueNames}
                prevalence={prevalence}
                actorCount={actorCount}
                tacticsCatalog={tacticsCatalog}
              />
            </BoardPanel>
          )}

          {/* hunt pack — collapsed reference. Renders whenever the profile HAS a
              fingerprint (the join input); floor-only packs still render (the
              links carry value and absence is stated, per doctrine). */}
          {fingerprint && huntPack && (
            <BoardPanel
              id="huntpack"
              collapsible
              eyebrow="Hunt pack"
              aside={
                huntPack.totalMatched > 0 ? (
                  <MicroLabel tone="faint">{num(huntPack.totalMatched)} queries</MicroLabel>
                ) : undefined
              }
            >
              <HuntPackPanel pack={huntPack} techniqueNames={techniqueNames} />
            </BoardPanel>
          )}

          {/* reporting — collapsed reference */}
          {reporting.length > 0 && (
            <BoardPanel
              id="reporting"
              collapsible
              eyebrow="Reporting"
              aside={<MicroLabel tone="faint">{num(reporting.length)}</MicroLabel>}
            >
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
        <div
          id="related"
          className="flex scroll-mt-[6.5rem] flex-col gap-5 lg:sticky lg:top-[6.5rem] lg:self-start"
        >
          {sharedActors && sharedActors.length > 0 && fingerprint && (
            <BoardPanel eyebrow="Shared techniques">
              <SharedTechniqueActors rows={sharedActors} selfTotal={fingerprint.techniques.length} />
            </BoardPanel>
          )}

          {fingerprint?.kind === 'malware' && usedBy && usedBy.length > 0 && (
            <BoardPanel eyebrow="Used by tracked groups">
              <UsedByGroups rows={usedBy} actorCount={actorCount} slugSet={slugSet} />
            </BoardPanel>
          )}

          {/* Omit only when the malware-page dedup emptied the list (a rendered
              "no related entities" there would be FALSE — the actors moved to the
              reverse-index). On pages with no reverse-index (usedBy absent) the
              panel still renders, keeping the genuinely-empty honest state. */}
          {(dedupedRelated.length > 0 || !usedBy?.length) && (
            <BoardPanel eyebrow="Related entities">
              <RelatedPanel related={dedupedRelated} />
            </BoardPanel>
          )}

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
