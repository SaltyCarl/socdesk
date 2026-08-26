import { cx } from '@socdesk/shared/lib/cx'
import type { HealthPayload } from './types'
import { rel } from './format'
import { CountUp } from './CountUp'
import { EmptyState } from './states'

/**
 * Collection health — is the pipeline actually collecting? One cell per
 * source: item count, last-success recency, and a status dot. Green/red here
 * is operational MEANING (online vs down), not a threat verdict, so the
 * reserved hues are earned. A degraded source shows its error verbatim rather
 * than hiding behind a green light.
 */

/** Pipeline warnings surface. A HEALTHY run can still emit dozens of
 *  low-severity drift notices (e.g. "DRIFT: CVE-… not in any seed group") — run
 *  together as one paragraph they turned this tab into a diagnostic dump. Show a
 *  handful inline as a scannable list; collapse a flood behind a count so the
 *  status the analyst actually came for stays legible. Content-agnostic — no
 *  brittle message-parsing, just a threshold. */
function PipelineWarnings({ warnings }: { warnings: string[] }) {
  const box =
    'rounded-md border border-[var(--edge-gold)] bg-[var(--tint-gold)] px-4 py-2.5 font-mono text-xs text-verdict-amber'
  const list = (
    <ul className="flex flex-col gap-1">
      {warnings.map((w) => (
        <li key={w} className="break-words">
          {w}
        </li>
      ))}
    </ul>
  )
  if (warnings.length <= 4) {
    return (
      <div role="alert" className={box}>
        {list}
      </div>
    )
  }
  return (
    <details className={box}>
      <summary className="cursor-pointer select-none font-semibold uppercase tracking-label">
        {warnings.length} pipeline warnings
      </summary>
      <div className="mt-2">{list}</div>
    </details>
  )
}

function StatusBanner({ ok, all }: { ok: number; all: number }) {
  const state = all > 0 && ok === all ? 'ok' : ok === 0 ? 'down' : 'partial'
  const skin =
    state === 'ok'
      ? 'border-[var(--edge-green)] bg-[var(--tint-green)] text-verdict-green'
      : state === 'down'
        ? 'border-[var(--edge-red)] bg-[var(--tint-red)] text-verdict-red'
        : 'border-[var(--edge-gold)] bg-[var(--tint-gold)] text-verdict-amber'
  const label =
    state === 'ok'
      ? 'All collectors online'
      : state === 'down'
        ? 'All collectors down'
        : 'Partial collection'
  return (
    <div className={cx('inline-flex items-center gap-2 rounded-md border px-3 py-1.5', skin)}>
      <span
        aria-hidden="true"
        className={cx(
          'inline-block size-2 rounded-full',
          state === 'ok' ? 'bg-verdict-green' : state === 'down' ? 'bg-verdict-red' : 'bg-verdict-amber',
        )}
      />
      <span className="font-mono text-micro font-semibold uppercase tracking-label">
        {label} · {ok}/{all}
      </span>
    </div>
  )
}

export function HealthView({ health }: { health: HealthPayload }) {
  const sources = health.sources ?? []
  const warnings = health.pipeline_warnings ?? []
  const ok = sources.filter((s) => s.ok).length

  if (!sources.length) {
    return (
      <EmptyState title="No collector health reported">
        The health snapshot is empty or has not published. Collectors report
        their status on each scheduled run.
      </EmptyState>
    )
  }

  return (
    <div className="flex flex-col gap-5">
      <StatusBanner ok={ok} all={sources.length} />

      {warnings.length > 0 && <PipelineWarnings warnings={warnings} />}

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {sources.map((s) => (
          <div
            key={s.source}
            className="sd-reveal flex flex-col gap-2 rounded-lg border border-line bg-panel p-4"
          >
            <div className="flex items-center justify-between gap-2">
              <span className="font-mono text-xs font-semibold uppercase tracking-label text-paper">
                {s.source}
              </span>
              <span
                aria-hidden="true"
                title={s.ok ? 'online' : 'degraded'}
                className={cx(
                  'inline-block size-2.5 rounded-full',
                  s.ok ? 'bg-verdict-green' : 'bg-verdict-red',
                )}
              />
            </div>
            <div
              className={cx(
                'font-display text-2xl font-extrabold tabular-nums',
                s.ok ? 'text-paper' : 'text-verdict-red',
              )}
            >
              <CountUp value={s.items} />
            </div>
            <div className="font-mono text-micro uppercase tracking-label text-faint">
              Last OK · {s.last_success_at ? rel(s.last_success_at) : 'NEVER'}
            </div>
            {!s.ok && s.error && (
              <div className="line-clamp-2 font-mono text-micro text-verdict-red">
                {s.error}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}
