import { cx } from '@socdesk/shared/lib/cx'
import type { HealthPayload } from '../views/types'
import { rel } from '../views/format'
import { DeskLink } from './board-ui'

/**
 * Collector status — did today's batch actually run? N/N online, the most-recent
 * ingest time, and any collector error printed VERBATIM (a degraded source is
 * never hidden behind a green light). Green/amber/red here is OPERATIONAL meaning
 * — online vs degraded vs down — not a threat verdict, so the reserved hues are
 * earned. The Health desk link beside it carries provenance, so no source stamp.
 */

function lastIngest(health: HealthPayload): string {
  const times = (health.sources ?? [])
    .map((s) => s.last_success_at)
    .filter(Boolean)
    .map((t) => Date.parse(t as string))
    .filter((n) => Number.isFinite(n))
  if (!times.length) return health.generated_at ? rel(health.generated_at) : '—'
  return rel(new Date(Math.max(...times)).toISOString())
}

export function FreshnessStrip({ health }: { health: HealthPayload }) {
  const sources = health.sources ?? []
  const ok = sources.filter((s) => s.ok).length
  const all = sources.length
  const state = all > 0 && ok === all ? 'ok' : ok === 0 ? 'down' : 'partial'

  const dot =
    state === 'ok' ? 'bg-verdict-green' : state === 'down' ? 'bg-verdict-red' : 'bg-verdict-amber'
  const label =
    state === 'ok' ? 'collectors online' : state === 'down' ? 'collectors down' : 'partial collection'

  // Degraded detail, verbatim: each down collector's error, plus pipeline warnings.
  const errors = [
    ...sources.filter((s) => !s.ok && s.error).map((s) => `${s.source}: ${s.error}`),
    ...(health.pipeline_warnings ?? []),
  ]

  return (
    <section className="sd-reveal flex flex-wrap items-center gap-x-5 gap-y-2 border-t border-line pt-3">
      <span className="inline-flex items-center gap-2">
        <span aria-hidden="true" className={cx('inline-block size-2 rounded-full', dot)} />
        <span className="font-mono text-micro font-semibold uppercase tracking-label text-paper">
          {ok}/{all} {label}
        </span>
      </span>

      <span aria-hidden="true" className="hidden h-4 w-px bg-line sm:block" />

      <span className="font-mono text-micro uppercase tracking-label text-faint">
        last ingest · <span className="text-muted">{lastIngest(health)}</span>
      </span>

      {errors.length > 0 && (
        <span className="font-mono text-micro text-verdict-amber" role="alert">
          {errors.join(' · ')}
        </span>
      )}

      <span className="ml-auto">
        <DeskLink tab="health">Health</DeskLink>
      </span>
    </section>
  )
}
