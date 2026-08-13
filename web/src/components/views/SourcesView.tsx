import { cx } from '@socdesk/shared/lib/cx'
import type { RegistrySource, RegistryPayload } from './types'
import { num, safeUrl } from './format'
import { EmptyState } from './states'

/**
 * The source registry — every collector and reference the desk draws on, named
 * openly. "Collectors" pull data into the pipeline; "reference" sources are
 * verification destinations. Transparency about provenance is the point:
 * nothing is consulted that isn't listed here.
 */

function KindTag({ kind }: { kind: string }) {
  const collector = kind === 'collector'
  return (
    <span
      className={cx(
        'inline-flex items-center rounded-sm border px-2 py-0.5 font-mono text-micro font-semibold uppercase tracking-label',
        collector
          ? 'border-[var(--edge-accent)] bg-[var(--tint-accent)] text-accent'
          : 'border-line bg-panel-soft text-muted',
      )}
    >
      {kind}
    </span>
  )
}

export function SourcesView({ registry }: { registry: RegistryPayload }) {
  const sources: RegistrySource[] = registry.sources ?? []
  const collectors = sources.filter((s) => s.kind === 'collector').length
  const references = sources.filter((s) => s.kind === 'reference').length

  if (!sources.length) {
    return (
      <EmptyState title="No sources registered">
        The registry is empty or has not published. It lists every collector
        and reference the desk consults.
      </EmptyState>
    )
  }

  return (
    <div className="flex flex-col gap-5">
      <div className="flex flex-wrap gap-x-6 gap-y-1 font-mono text-micro uppercase tracking-label text-faint">
        <span>
          <b className="text-accent">{num(collectors)}</b> collectors
        </span>
        <span>
          <b className="text-paper">{num(references)}</b> reference
        </span>
      </div>

      <div className="overflow-x-auto rounded-lg border border-line">
        <table className="w-full min-w-[640px] border-collapse text-left">
          <thead>
            <tr>
              {['Source', 'Kind', 'Coverage', 'Reference'].map((h, i) => (
                <th
                  key={h}
                  scope="col"
                  className={cx(
                    'border-b border-line bg-panel px-3 py-2.5 font-mono text-micro font-semibold uppercase tracking-label text-faint',
                    i === 3 && 'text-right',
                  )}
                >
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {sources.map((s) => {
              const url = safeUrl(s.url)
              return (
                <tr
                  key={s.name}
                  className="border-b border-line align-top last:border-0 transition-colors duration-150 ease-brand hover:bg-panel-soft"
                >
                  <td className="px-3 py-2.5 text-xs font-semibold text-paper">
                    {s.name}
                  </td>
                  <td className="px-3 py-2.5">
                    <KindTag kind={s.kind} />
                  </td>
                  <td className="px-3 py-2.5 text-xs text-muted">
                    {s.coverage || '—'}
                  </td>
                  <td className="whitespace-nowrap px-3 py-2.5 text-right">
                    {url ? (
                      <a
                        href={url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="font-mono text-micro uppercase tracking-label text-accent underline-offset-2 hover:underline"
                      >
                        Open ↗
                      </a>
                    ) : (
                      <span className="font-mono text-micro text-faint">—</span>
                    )}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}
