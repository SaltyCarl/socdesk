import { useMemo } from 'react'
import { cx } from '@socdesk/shared/lib/cx'
import { MicroLabel } from '../ui'
import { MonoTag } from './Badges'
import { rel, safeUrl, num } from './format'
import { PIVOTABLE, provenance, techniqueUrl } from './relations'
import { ActorLink } from '../overview/board-ui'
import type { ProfileResult } from './profiles'

/**
 * ActorProfile — the fused info-card for one threat actor / ransomware group /
 * malware family, addressed by `/actor#g=<slug>`.
 *
 * Honesty doctrine (shared/verdict/doctrine.ts): SOCDesk emits no verdict of its
 * own and never synthesises intelligence. Every section degrades to a DISTINCT
 * honest empty — no fingerprint, no leak-site activity, no reporting, no
 * relations are each stated in their own words rather than hidden or faked.
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

/* ---------------- fingerprint (MITRE or activity) ---------------- */

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

function ActivityFingerprintPanel({
  ransomware,
  apt,
}: {
  ransomware: ProfileResult['ransomware']
  apt: boolean
}) {
  // Ransomware-only vs reporting-only actor get DIFFERENT honest lines.
  if (!ransomware) {
    return (
      <p className="text-xs leading-relaxed text-muted">
        {apt
          ? 'No ATT&CK profile on file for this actor — the intelligence below is drawn from open-source reporting, attributed to each outlet.'
          : 'No ATT&CK profile and no leak-site activity on file for this entity in the current snapshot.'}
      </p>
    )
  }
  return (
    <div className="flex flex-col gap-5">
      <p className="text-xs leading-relaxed text-muted">
        Ransomware-only group — no ATT&amp;CK profile on file. The fingerprint below is drawn from
        observed leak-site activity, not an encyclopedia entry.
      </p>

      <div className="flex flex-col gap-1">
        <SectionLabel>Leak-site claims in window</SectionLabel>
        <span className="font-display text-lg font-extrabold tabular-nums text-paper">
          {num(ransomware.totalClaims)}
        </span>
      </div>

      <div className="flex flex-col gap-2">
        <SectionLabel>Target sectors</SectionLabel>
        {ransomware.sectors.length ? (
          <div className="flex flex-wrap gap-1.5">
            {ransomware.sectors.map((s) => (
              <span
                key={s}
                className="rounded-sm border border-line bg-panel-soft px-1.5 py-0.5 font-mono text-micro text-muted"
              >
                {s}
              </span>
            ))}
          </div>
        ) : (
          <p className="text-xs text-muted">No sector attributed by the source.</p>
        )}
      </div>

      <div className="flex flex-col gap-2">
        <SectionLabel>Target countries</SectionLabel>
        {ransomware.countries.length ? (
          <>
            <div className="flex flex-wrap gap-1.5">
              {ransomware.countries.map((c) => (
                <span
                  key={c}
                  className="rounded-sm border border-line bg-panel-soft px-1.5 py-0.5 font-mono text-micro text-muted"
                >
                  {c}
                </span>
              ))}
            </div>
            <p className="text-micro text-faint">
              Partial — rolled-up digest claims omit country, so more countries may be affected.
            </p>
          </>
        ) : (
          <p className="text-xs text-muted">No country attributed by the source.</p>
        )}
      </div>
    </div>
  )
}

/* ---------------- recent activity ---------------- */

function RansomwareClaims({ ransomware }: { ransomware: NonNullable<ProfileResult['ransomware']> }) {
  return (
    <div className="flex flex-col divide-y divide-line">
      {ransomware.items.map((it) => {
        const href = safeUrl(it.url)
        const onion = /\.onion(\/|$|:)/i.test(it.url)
        return (
          <div key={it.id} className="flex flex-col gap-1.5 py-3 first:pt-0">
            <div className="flex flex-wrap items-center gap-2">
              {it.grouped != null ? (
                <MonoTag tone="accent">digest · {num(it.grouped)}</MonoTag>
              ) : (
                <MonoTag tone="faint">claim</MonoTag>
              )}
              {it.sector && <span className="font-mono text-micro text-muted">{it.sector}</span>}
              {it.country && <span className="font-mono text-micro text-faint">{it.country}</span>}
              <span className="ml-auto whitespace-nowrap font-mono text-micro text-faint">
                {rel(it.published_at)}
              </span>
            </div>
            <span className="text-base text-paper">{it.title}</span>
            {href && (
              <ExternalLink href={href} onion={onion}>
                Claim source
              </ExternalLink>
            )}
          </div>
        )
      })}
      <p className="pt-3 text-micro text-faint">
        Victim names are withheld per policy — only the sector / country the leak site attributed is
        shown.
      </p>
    </div>
  )
}

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

/* ---------------- related (MITRE only) ---------------- */

function RelatedPanel({ related }: { related: ProfileResult['related'] }) {
  if (!related.length) {
    return (
      <p className="text-xs text-muted">
        No related entities recorded — this profile has no ATT&amp;CK links or feed co-occurrences in
        this snapshot.
      </p>
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

/* ---------------- header badges ---------------- */

function KindBadges({ profile }: { profile: ProfileResult }) {
  const fp = profile.fingerprint
  return (
    <div className="flex flex-wrap items-center gap-1.5">
      {profile.ransomware && <MonoTag tone="accent">Ransomware group</MonoTag>}
      {fp?.kind === 'actor' && <MonoTag tone="accent">ATT&amp;CK {fp.attack_id}</MonoTag>}
      {fp?.kind === 'malware' && <MonoTag tone="muted">Malware {fp.attack_id}</MonoTag>}
      {!fp && profile.reporting.length > 0 && <MonoTag tone="muted">APT / reported</MonoTag>}
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
  const { fingerprint, ransomware, reporting } = profile
  const attackHref = useMemo(() => safeUrl(fingerprint?.attackUrl), [fingerprint])
  const isApt = !fingerprint && reporting.length > 0

  return (
    <div className="flex flex-col gap-5">
      {/* header */}
      <div className="flex flex-col gap-3 rounded-lg border border-line bg-raised p-5 shadow-e1">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="flex flex-col gap-2">
            <KindBadges profile={profile} />
            <h1 className="font-display text-xl font-extrabold tracking-tight text-paper">
              {profile.name}
            </h1>
            <span className="font-mono text-micro text-faint">
              {fingerprint?.attack_id ? `${fingerprint.attack_id} · ` : ''}g={profile.slug}
            </span>
          </div>
          {attackHref && (
            <a
              href={attackHref}
              target="_blank"
              rel="noopener noreferrer"
              className="font-mono text-micro text-accent underline-offset-2 hover:underline"
            >
              {fingerprint?.attack_id} on ATT&amp;CK ↗
            </a>
          )}
        </div>
      </div>

      <div className="grid gap-5 lg:grid-cols-[1fr_340px]">
        <div className="flex flex-col gap-5">
          {/* fingerprint */}
          <section className="flex flex-col gap-4 rounded-lg border border-line bg-panel p-5">
            <SectionLabel accent>Fingerprint</SectionLabel>
            {fingerprint ? (
              <MitreFingerprintPanel fingerprint={fingerprint} slugSet={slugSet} />
            ) : (
              <ActivityFingerprintPanel ransomware={ransomware} apt={isApt} />
            )}
          </section>

          {/* recent activity */}
          <section className="flex flex-col gap-4 rounded-lg border border-line bg-panel p-5">
            <SectionLabel accent>Recent activity</SectionLabel>
            {ransomware ? (
              <RansomwareClaims ransomware={ransomware} />
            ) : reporting.length ? (
              <ReportingList reporting={reporting} />
            ) : (
              <p className="text-xs text-muted">
                No leak-site claims or reporting name this entity in the current window.
              </p>
            )}
            {/* When a group has BOTH claims and reporting, surface the reporting too. */}
            {ransomware && reporting.length > 0 && (
              <div className="flex flex-col gap-3 border-t border-line pt-4">
                <SectionLabel>Also in reporting</SectionLabel>
                <ReportingList reporting={reporting} />
              </div>
            )}
          </section>
        </div>

        {/* related */}
        <div className="lg:sticky lg:top-20 lg:self-start">
          <section className="flex flex-col gap-4 rounded-lg border border-line bg-panel p-5">
            <SectionLabel accent>Related entities</SectionLabel>
            <RelatedPanel related={profile.related} />
          </section>
        </div>
      </div>
    </div>
  )
}
