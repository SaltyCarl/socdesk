import { cx } from '@socdesk/shared/lib/cx'
import { num, rel } from './format'
import { TechniqueChip } from './TechniqueChip'
import { HeatStrip } from './HeatStrip'
import { distinctiveSplit } from './derived'
import type { HuntPack } from './huntpack'
import type { MitreFingerprint, ProfileActivity } from './profiles'
import type { CveContext, RansomIntel } from './types'

/**
 * SynthesisBand — the always-open decision layer's one-screen read. Four signal
 * cells, each honest-empty on its own; the whole band returns null when none has
 * data (a bare MITRE actor shows nothing here). Every cell is a ROUTER: its label
 * deep-links to the full (collapsed) section, so the synthesis leads and the depth
 * is one click away. No new analysis — it re-surfaces existing artifacts
 * (distinctiveSplit / huntPack / activity.daily / intel) as the lead.
 */
function CellLabel({ href, children }: { href?: string; children: React.ReactNode }) {
  const cls = 'font-mono text-micro uppercase tracking-label text-faint'
  return href ? (
    <a href={href} className={cx(cls, 'transition-colors duration-150 ease-brand hover:text-accent')}>
      {children}
    </a>
  ) : (
    <span className={cls}>{children}</span>
  )
}

export function SynthesisBand({
  fingerprint,
  prevalence,
  actorCount,
  huntPack,
  activity,
  intel,
  cveContext,
  techniqueNames,
}: {
  fingerprint: MitreFingerprint | null
  prevalence?: Map<string, number>
  actorCount?: number
  huntPack?: HuntPack
  activity: ProfileActivity | null
  intel: RansomIntel | null
  cveContext?: Record<string, CveContext>
  techniqueNames?: Record<string, string>
}) {
  // N4: the differentiated artifact, promoted from an in-matrix tint to the lead.
  const distinctive =
    fingerprint && prevalence ? distinctiveSplit(fingerprint.techniques, prevalence).distinctive : []
  const huntTitles =
    huntPack && huntPack.totalMatched > 0
      ? huntPack.sections.flatMap((s) => s.rows).map((r) => r.rule.title)
      : []
  const hasSpark = Boolean(activity && activity.daily.length > 0)
  const cves = intel?.initial_access_cves ?? []

  const cells: React.ReactNode[] = []

  if (distinctive.length > 0) {
    cells.push(
      <div key="ttp" className="flex flex-col gap-2">
        <CellLabel href="#fingerprint">Distinctive TTPs · {num(distinctive.length)}</CellLabel>
        <div className="flex flex-wrap items-center gap-1.5">
          {distinctive.slice(0, 5).map((t) => (
            <TechniqueChip key={t} id={t} name={techniqueNames?.[t]} distinctive />
          ))}
          {distinctive.length > 5 && (
            <span className="font-mono text-micro text-faint">+{num(distinctive.length - 5)}</span>
          )}
        </div>
        {actorCount ? (
          <span className="text-micro text-faint">
            rare — each used by ≤3 of {num(actorCount)} tracked groups
          </span>
        ) : null}
      </div>,
    )
  }

  if (huntTitles.length > 0) {
    cells.push(
      <div key="hunts" className="flex flex-col gap-2">
        <CellLabel href="#huntpack">Top hunts · {num(huntPack!.totalMatched)}</CellLabel>
        <ul className="flex flex-col gap-1 text-xs text-muted">
          {huntTitles.slice(0, 3).map((t, i) => (
            <li key={i} className="line-clamp-1">
              {t}
            </li>
          ))}
        </ul>
      </div>,
    )
  }

  if (hasSpark && activity) {
    cells.push(
      <div key="activity" className="flex flex-col gap-2">
        <CellLabel href="#activity">Recent activity</CellLabel>
        <HeatStrip compact daily={activity.daily} />
        <span className="font-mono text-micro text-faint">
          {num(activity.victimCount)} claim{activity.victimCount === 1 ? '' : 's'}
          {activity.lastClaimAt ? ` · last ${rel(activity.lastClaimAt)}` : ''}
        </span>
      </div>,
    )
  }

  if (cves.length > 0) {
    // A terse tease, NOT a chip duplicate — the full "Initial access & detection"
    // panel is always open right below (the CVE chips + EPSS/KEV live there). This
    // cell just flags the count + KEV pressure so the glance reads.
    const kevCount = cveContext ? cves.filter((c) => cveContext[c]?.kev).length : 0
    cells.push(
      <div key="cves" className="flex flex-col gap-2">
        <CellLabel>Initial access</CellLabel>
        <span className="text-xs text-muted">
          {num(cves.length)} initial-access CVE{cves.length === 1 ? '' : 's'}
          {kevCount > 0 ? ` · ${num(kevCount)} in CISA KEV` : ''}
        </span>
      </div>,
    )
  }

  if (cells.length === 0) return null

  return (
    <section aria-label="At a glance" className="rounded-lg border border-line bg-panel-soft p-4">
      <div className="grid gap-4 sm:grid-cols-2">{cells}</div>
    </section>
  )
}
