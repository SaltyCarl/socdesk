import { MicroLabel } from '@socdesk/shared/ui'
import { cx } from '@socdesk/shared/lib/cx'
import type { InlineEnrichState } from './useInlineEnrich'

/** Honest non-ok renderings for the inline IOC lookup (never a fabricated
 *  verdict). `idle`/`ok` return null — the caller renders those. */
export function InlineLookupStatus({ state }: { state: InlineEnrichState }) {
  if (state.kind === 'checking') {
    return (
      <div className="flex items-center gap-3 rounded-lg border border-line bg-panel p-4" role="status" aria-live="polite">
        <span aria-hidden="true" className="size-4 shrink-0 rounded-full border-2 border-line-bright border-t-accent motion-safe:animate-spin" />
        <span className="break-all font-mono text-xs text-muted">Checking {state.indicator}…</span>
      </div>
    )
  }
  if (state.kind === 'declined' || state.kind === 'unavailable' || state.kind === 'unsupported') {
    const amber = state.kind === 'declined'
    const title =
      state.kind === 'declined' ? 'The enrichment endpoint declined this indicator'
      : state.kind === 'unavailable' ? 'Live lookup is unavailable'
      : 'Not a live-enriched indicator'
    const body = state.kind === 'unsupported'
      ? 'Live lookup covers IPs, domains, URLs and file hashes.'
      : `${state.reason}.`
    return (
      <div className={cx('flex flex-col gap-1.5 rounded-lg border bg-panel p-4', amber ? 'border-[var(--edge-gold)]' : 'border-line')} role="status">
        <MicroLabel tone="faint">{state.kind}</MicroLabel>
        <p className={cx('font-display text-sm font-bold leading-snug', amber ? 'text-verdict-amber' : 'text-paper')}>{title}</p>
        <p className="text-xs leading-relaxed text-muted">{body}</p>
      </div>
    )
  }
  return null
}
