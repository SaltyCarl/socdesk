// useCockpitInput — the ONE hook that turns a committed omnibox value into a
// same-shaped result the cockpit renders, whichever surface it belongs to
// (design spec §3.3). Classifies with `classifyCockpitInput` (shared/intent.ts
// — the data-boundary guard, run BEFORE either downstream hook sees the raw
// value), then calls BOTH `useLookup` and `usePsAnalysis` unconditionally
// (rules-of-hooks) — the unselected one is fed `''`, which both hooks already
// short-circuit to their own `idle` state for free (useLookup.ts:52,
// usePsAnalysis.ts:16-17), so nothing extra is fetched or analyzed.
//
// `submitted` MUST be the COMMITTED (post-Enter) value, never the live-typed
// one — useLookup has no debounce of its own, so feeding it a live value
// would hammer /api/enrich on every keystroke (design spec §1, §7).
//
// `useCockpitInput` itself calls two real React hooks internally and so,
// like `useLookup`/`usePsAnalysis` (neither of which has a dedicated unit
// test in this repo), is not independently unit-tested — there is no
// jsdom/React Testing Library harness here. Its correctness rides on the
// pure `resolveCockpitArgs` routing step below (fully tested) plus the
// tsc/build gate on every task that consumes it.

import { classifyCockpitInput, type CockpitInputKind } from '@socdesk/shared/intent'
import { useLookup, type LookupState } from '../lookup/useLookup'
import { usePsAnalysis, type PsState } from '../analyzer/usePsAnalysis'

export type CockpitResult =
  | { kind: 'indicator'; state: LookupState }
  | { kind: 'command'; state: PsState }
  | { kind: 'unclassified'; state: { kind: 'idle' } }

// A stable reference for the unclassified branch's state — without this, a
// fresh `{ kind: 'idle' }` object literal every render would defeat any
// caller effect keyed on `cockpit.state` (e.g. Overview.tsx's globe-landing
// effect), re-firing on every incidental re-render even though nothing about
// the result actually changed.
const IDLE = { kind: 'idle' } as const

/** Pure routing step: which committed value (if any) each downstream hook
 *  should receive for a given classified `kind`. Exported and unit-tested on
 *  its own (see useCockpitInput.test.ts). */
export function resolveCockpitArgs(
  kind: CockpitInputKind,
  submitted: string,
): { indicatorArg: string; commandArg: string } {
  return {
    indicatorArg: kind === 'indicator' ? submitted : '',
    commandArg: kind === 'command' ? submitted : '',
  }
}

/** Apply the ModeChip override monotonically: it may escalate a missed
 *  indicator/unclassified value TO 'command', but must NEVER pull an
 *  auto-detected 'command' away from 'command' — doing so would feed the raw
 *  script to useLookup → /api/enrich (design spec §2.1). */
export function resolveKind(
  autoKind: CockpitInputKind,
  override: 'indicator' | 'command' | null,
): CockpitInputKind {
  if (autoKind === 'command') return 'command'
  return override ?? autoKind
}

/**
 * `override`, when set, wins over auto-detection for this submission — the
 * ModeChip's correction (design spec §3.7, Task 7) — EXCEPT it can never pull
 * an auto-detected 'command' away from 'command' (`resolveKind` above,
 * design spec §2.1's monotonic guard). Defaults to auto-detect.
 */
export function useCockpitInput(
  submitted: string,
  override: 'indicator' | 'command' | null = null,
): CockpitResult {
  const kind: CockpitInputKind = resolveKind(classifyCockpitInput(submitted), override)
  const { indicatorArg, commandArg } = resolveCockpitArgs(kind, submitted)
  const lookupState = useLookup(indicatorArg)
  const psState = usePsAnalysis(commandArg)

  if (kind === 'indicator') return { kind, state: lookupState }
  if (kind === 'command') return { kind, state: psState }
  return { kind: 'unclassified', state: IDLE }
}
