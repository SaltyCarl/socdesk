import type { ReactNode } from 'react'
import { MicroLabel } from '../ui'
import { useStateData } from '../views/useStateData'
import { AsyncGate, Skeleton, SkeletonRows } from '../views/states'
import { day, rel } from '../views/format'
import type {
  CvePayload,
  FeedPayload,
  HealthPayload,
  TrendsPayload,
} from '../views/types'
import { SinceYesterday } from './SinceYesterday'
import { TopOfQueue } from './TopOfQueue'
import { NewToKev } from './NewToKev'
import { ExploitedNotSevere } from './ExploitedNotSevere'
import { FreshnessStrip } from './FreshnessStrip'
import { useInView } from './useInView'

/**
 * The start-of-shift situational board that fills the Overview below the globe.
 * Ordered to walk a shift open in one scroll: what changed → what's hot & why →
 * the judgment we bring → verify our plumbing.
 *
 * HONESTY is a feature here, not a disclaimer: the section is framed as a
 * daily-batch read (not "live"), every figure names its source file, and every
 * panel degrades to a truthful empty rather than inventing a row. No fake
 * live-attack map, geo heatmap, or synthesized threat gauge — this tool runs no
 * sensors and says so.
 *
 * PERF: trends (826 B), feed (293 KB) and health (540 B) fetch on mount; the
 * heavy cves.json (~5 MB) is DEFERRED behind an IntersectionObserver so the
 * landing paints without pulling the catalog until the analyst scrolls toward
 * the panel that needs it.
 */

/* ---------------- deferred cves panel ---------------- */

function ExploitedSkeleton() {
  return (
    <div className="flex min-h-[18rem] flex-col gap-4 rounded-lg border border-[var(--edge-accent)] bg-raised p-5 shadow-e1">
      <Skeleton className="h-4 w-40" />
      <div className="flex flex-col gap-6 lg:flex-row lg:gap-8">
        <SkeletonRows rows={4} className="flex-1" />
        <SkeletonRows rows={4} className="flex-1" />
      </div>
    </div>
  )
}

function ExploitedLoader() {
  const { status, data, error } = useStateData<CvePayload>('cves')
  return (
    <AsyncGate
      status={status}
      label="the vulnerability catalog"
      detail={error}
      skeleton={<ExploitedSkeleton />}
    >
      <ExploitedNotSevere cves={data?.cves ?? []} />
    </AsyncGate>
  )
}

/** Gates the ~5 MB cves.json fetch until this slot nears the viewport. */
function DeferredExploited() {
  const { ref, inView } = useInView<HTMLDivElement>()
  return <div ref={ref}>{inView ? <ExploitedLoader /> : <ExploitedSkeleton />}</div>
}

/* ---------------- section header (the honesty frame) ---------------- */

function BoardHeader({ generatedAt }: { generatedAt?: string }) {
  return (
    <header className="flex flex-col gap-3 border-t border-line pt-8 sm:flex-row sm:items-end sm:justify-between">
      <div className="flex flex-col gap-2">
        <MicroLabel tone="accent" tick>
          Start of shift
        </MicroLabel>
        <h2 className="font-display text-xl font-extrabold tracking-tight text-paper">
          Situational board
        </h2>
        <p className="max-w-2xl text-base text-muted">
          Where a shift opens: what changed overnight, what&rsquo;s hot and why,
          the calls we bring, and whether the plumbing ran. A daily-batch read —
          not a live feed.
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

/* ---------------- a thin gate for the strip/tile panels ---------------- */

function Gate({
  status,
  label,
  detail,
  skeleton,
  children,
}: {
  status: 'loading' | 'ready' | 'error'
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

  const generatedAt =
    trends.data?.generated_at ?? feed.data?.generated_at ?? health.data?.generated_at

  return (
    <section aria-label="Start-of-shift situational board" className="mt-6 flex flex-col gap-5">
      <BoardHeader generatedAt={generatedAt} />

      {/* 1 · what changed */}
      <Gate
        status={trends.status}
        label="the trend snapshot"
        detail={trends.error}
        skeleton={<Skeleton className="h-20 w-full rounded-lg" />}
      >
        <SinceYesterday trends={trends.data ?? {}} />
      </Gate>

      {/* 2 · what's hot   +   4 · newly exploited */}
      <div className="grid grid-cols-1 gap-5 lg:grid-cols-3">
        <div className="lg:col-span-2">
          <Gate
            status={feed.status}
            label="the feed"
            detail={feed.error}
            skeleton={<Skeleton className="h-80 w-full rounded-lg" />}
          >
            <TopOfQueue items={feed.data?.items ?? []} />
          </Gate>
        </div>
        <div className="lg:col-span-1">
          <Gate
            status={trends.status}
            label="the trend snapshot"
            detail={trends.error}
            skeleton={<Skeleton className="h-80 w-full rounded-lg" />}
          >
            <NewToKev entries={trends.data?.new_kev ?? []} />
          </Gate>
        </div>
      </div>

      {/* 3 · the judgment we bring (deferred heavy fetch) */}
      <DeferredExploited />

      {/* 5 · verify our plumbing */}
      <Gate
        status={health.status}
        label="collector health"
        detail={health.error}
        skeleton={<Skeleton className="h-12 w-full rounded-lg" />}
      >
        <FreshnessStrip health={health.data ?? { sources: [] }} />
      </Gate>
    </section>
  )
}
