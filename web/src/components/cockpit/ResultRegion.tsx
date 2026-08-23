import { EscalationCard, type CompareResult, type EffectiveTheme } from '@socdesk/shared/verdict-cards'
import { LookupStatus } from '../lookup/LookupStates'
import { AnalyzerResult, type PsState } from '@socdesk/shared/analyzer-ui'
import { isEnrichable } from '@socdesk/shared/indicators'
import { ReportButton } from '../report/ReportButton'
import type { CockpitResult } from './useCockpitInput'

/** A light "Analyzing…" line for the command path — the same honest-status
 *  register as LookupStatus's Checking, but for the (synchronous, near-
 *  instant) analyzer. `idle` and `ok` are handled by the caller. */
function PsStatus({ state }: { state: Extract<PsState, { kind: 'analyzing' } | { kind: 'error' }> }) {
  if (state.kind === 'analyzing') {
    return <p className="font-mono text-micro text-faint">Analyzing…</p>
  }
  return <p className="font-mono text-xs text-muted">Could not analyze: {state.message}</p>
}

/**
 * The cockpit's mode-aware result slot (design spec §3.5) — replaces the old
 * hard `LandingResult` switch. Dispatches on `cockpit.kind` FIRST, then on
 * each hook's own state union:
 *
 *   indicator     -> EscalationCard (ok) | LookupStatus (checking/declined/
 *                    unavailable/unsupported), unchanged from the old
 *                    LandingResult.
 *   command       -> AnalyzerResult (ok) | PsStatus (analyzing/error).
 *   unclassified  -> an honest one-line hint naming both accepted input kinds.
 *
 * The caller keys its wrapper on the COMPOSITE `key={`${cockpit.kind}:
 * ${submitted}`}` (Overview.tsx, Task 7 — carried forward from Task 6's
 * `key={cockpit.kind}`) so either a kind flip OR a new committed value fully
 * unmounts the previous subtree. The composite matters once a ModeChip
 * override can flip `kind` on the SAME committed string (e.g. forcing an IP
 * to be treated as a command) — `submitted` alone wouldn't change, so a key
 * on `submitted` alone would fail to remount. This is what stops
 * EscalationCard's CompareIp second-fetch from surviving a switch to the
 * analyzer and firing against stale state (design spec §2.3, §7).
 */
export function ResultRegion({
  cockpit,
  theme,
  onCompare,
}: {
  cockpit: CockpitResult
  theme: EffectiveTheme
  onCompare: (c: CompareResult | null) => void
}) {
  if (cockpit.kind === 'indicator') {
    const { state } = cockpit
    if (state.kind === 'idle') return null
    return (
      <div className="flex w-full max-w-md flex-col gap-3">
        {state.kind === 'ok' ? (
          <EscalationCard
            data={state.data}
            theme={theme}
            onCompare={onCompare}
            reportSlot={
              isEnrichable(state.data.type) ? (
                <ReportButton iocType={state.data.type} iocValue={state.data.indicator} />
              ) : undefined
            }
          />
        ) : (
          <LookupStatus state={state} />
        )}
      </div>
    )
  }

  if (cockpit.kind === 'command') {
    const { state } = cockpit
    if (state.kind === 'idle') return null
    if (state.kind === 'ok') return <AnalyzerResult result={state.result} />
    return <PsStatus state={state} />
  }

  // unclassified — an honest hint, never a fabricated result (reuses the
  // unrecognised voice from LookupStates.tsx:119-127). Only ever mounted
  // once something has been submitted — the caller gates on `isResult`.
  return (
    <p className="font-mono text-xs text-muted">
      Not a recognised indicator or command — paste an IP, domain, hash, URL, CVE, or a PowerShell
      command.
    </p>
  )
}
