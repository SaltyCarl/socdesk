import { useMemo, type ReactNode } from 'react'
import { MicroLabel } from '../ui'
import { useStateData, type AsyncStatus } from '../views/useStateData'
import { AsyncGate, Skeleton, SkeletonRows } from '../views/states'
import { day, rel } from '../views/format'
import type { CvePayload, FeedPayload, HealthPayload, TrendsPayload } from '../views/types'
import { OverviewStats } from './OverviewStats'
import { WhatChanged } from './WhatChanged'
import { RansomwareActivity } from './RansomwareActivity'
import { NamedActorActivity } from './NamedActorActivity'
import { PatchPriority } from './PatchPriority'
import { FreshnessStrip } from './FreshnessStrip'
import { aggregateRansomware, namedActorReports } from './aggregations'
import { useInView } from './useInView'

/**
 * Daily threat summary — the board below the globe. It answers four DIFFERENT
 * questions rather than three cuts of the same CVE table:
 *   who is hitting people   → Ransomware activity (leak-site victim claims)
 *   who is being reported on → Named-actor activity (APT / campaign)
 *   what to patch first      → Patch priority (KEV / EPSS)
 *   did collection run       → Collector status
 * plus a mixed stat strip on top. Each panel ranks its OWN lane — the feed's
 * category-capped score makes a single global "top" list an all-CVE artifact.
 *
 * HONESTY holds: framed as a once-daily summary (not live), every panel degrades
 * to a truthful empty, and sources cite the upstream authority. No fabricated
 * live-attack map, geo heatmap, or synthesized threat gauge.
 *
 * PERF: trends (826 B), feed (293 KB) and health (540 B) fetch on mount; the
 * heavy cves.json (~5 MB) is DEFERRED behind an IntersectionObserver so the
 * landing paints before the catalog is pulled.
 */

/* ---------------- deferred patch-priority panel (heavy cves fetch) ---------------- */

function PatchSkeleton() {
  return (
    <div className="flex h-full min-h-[18rem] flex-col gap-4 rounded-lg border border-line bg-panel p-5">
      <Skeleton className="h-4 w-40" />
      <SkeletonRows rows={6} />
    </div>
  )
}

function PatchLoader() {
  const { status, data, error } = useStateData<CvePayload>('cves')
  return (
    <AsyncGate
      status={status}
      label="the vulnerability catalog"
      detail={error}
      skeleton={<PatchSkeleton />}
    >
      <PatchPriority cves={data?.cves ?? []} />
    </AsyncGate>
  )
}

/** Gates the ~5 MB cves.json fetch until this slot nears the viewport. */
function DeferredPatch() {
  const { ref, inView } = useInView<HTMLDivElement>()
  return (
    <div ref={ref} className="h-full">
      {inView ? <PatchLoader /> : <PatchSkeleton />}
    </div>
  )
}

/* ---------------- header (de-LARPed, honest frame) ---------------- */

function BoardHeader({ generatedAt }: { generatedAt?: string }) {
  return (
    <header className="flex flex-col gap-3 border-t border-line pt-8 sm:flex-row sm:items-end sm:justify-between">
      <div className="flex flex-col gap-2">
        <MicroLabel tone="accent" tick>
          Daily summary
        </MicroLabel>
        <h2 className="font-display text-xl font-extrabold tracking-tight text-paper">
          Daily threat summary
        </h2>
        <p className="max-w-2xl text-base text-muted">
          A once-daily summary — what changed in the last 24 hours, active
          ransomware and named-actor reporting, and what to patch first. Updated
          once per day, not a live feed.
        </p>
      </div>
      {generatedAt && (
        <MicroLabel tone="faint" className="shrink-0 whitespace-nowrap">
          as of {day(generatedAt)} · {rel(generatedAt)}
        </MicroLabel>
      )}
    </header>
  )
}

/* ---------------- gate helper + status combiner ---------------- */

function combine(a: AsyncStatus, b: AsyncStatus): AsyncStatus {
  if (a === 'error' || b === 'error') return 'error'
  if (a === 'ready' && b === 'ready') return 'ready'
  return 'loading'
}

function Gate({
  status,
  label,
  detail,
  skeleton,
  children,
}: {
  status: AsyncStatus
  label: string
  detail: string | null
  skeleton: ReactNode
  children: ReactNode
}) {
  return (
    <AsyncGate status={status} label={label} detail={detail} skeleton={skeleton}>
      {children}
    </AsyncGate>
  )
}

/* ---------------- the board ---------------- */

export function SituationalBoard() {
  const trends = useStateData<TrendsPayload>('trends')
  const feed = useStateData<FeedPayload>('feed')
  const health = useStateData<HealthPayload>('health')

  const items = useMemo(() => feed.data?.items ?? [], [feed.data])
  const ransom = useMemo(() => aggregateRansomware(items), [items])
  const actorReports = useMemo(() => namedActorReports(items), [items])

  const generatedAt =
    trends.data?.generated_at ?? feed.data?.generated_at ?? health.data?.generated_at

  // Rhythm by SPACE, not rules: three blocks separated by a wide gap-8 seam, each
  // block cohering its own panels at gap-4. The flagship sits alone in the middle
  // block so it reads as the centrepiece; intro+stats lead, the secondary lane
  // (reporting · patch · collector) trails.
  return (
    <section aria-label="Daily threat summary" className="mt-6 flex flex-col gap-8">
      {/* intro + mixed stat strip (vuln + ransomware + volume) */}
      <div className="flex flex-col gap-4">
        <BoardHeader generatedAt={generatedAt} />
        <Gate
          status={combine(trends.status, feed.status)}
          label="the daily totals"
          detail={trends.error ?? feed.error}
          skeleton={<Skeleton className="h-20 w-full rounded-lg" />}
        >
          <OverviewStats trends={trends.data ?? {}} ransom={ransom} />
        </Gate>
      </div>

      {/* what changed — the granular lists behind the stat strip's KEV/EPSS
          deltas; light trends.json only, so no heavy fetch */}
      <Gate
        status={trends.status}
        label="what changed this week"
        detail={trends.error}
        skeleton={<Skeleton className="h-72 w-full rounded-lg" />}
      >
        <WhatChanged trends={trends.data ?? {}} />
      </Gate>

      {/* flagship — who's hitting people right now */}
      <Gate
        status={feed.status}
        label="ransomware activity"
        detail={feed.error}
        skeleton={<Skeleton className="h-72 w-full rounded-lg" />}
      >
        <RansomwareActivity summary={ransom} />
      </Gate>

      {/* secondary lane: who's reported on · what to patch · did collection run */}
      <div className="flex flex-col gap-4">
        <div className="grid grid-cols-1 items-stretch gap-4 lg:grid-cols-2">
          <Gate
            status={feed.status}
            label="named-actor reporting"
            detail={feed.error}
            skeleton={<Skeleton className="h-80 w-full rounded-lg" />}
          >
            <NamedActorActivity reports={actorReports} />
          </Gate>

          <DeferredPatch />
        </div>

        <Gate
          status={health.status}
          label="collector status"
          detail={health.error}
          skeleton={<Skeleton className="h-12 w-full rounded-lg" />}
        >
          <FreshnessStrip health={health.data ?? { sources: [] }} />
        </Gate>
      </div>
    </section>
  )
}
