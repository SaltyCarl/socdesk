// Panel.tsx — the side-panel surface: local analyzer for a command, the
// shared escalation card for an indicator.
//
// DATA BOUNDARY: a `command`-classified handoff is analyzed LOCALLY via
// usePsAnalysis (shared/analyzer, pure client-side logic) and NEVER reaches
// /api/enrich. Only an indicator — the lookup handoff, or whatever the paste
// box re-routes to via routeSelection — calls fetchEnrich, and only with the
// resolved `baseUrl` origin. AnalyzeBody never touches fetchEnrich.
//
// The panel can MOUNT before the background's chrome.storage.session.set
// lands (side panels open asynchronously), so the pending handoff is read
// both on mount AND via chrome.storage.onChanged for the session area.
//
// MV3 side panels persist for the page lifetime and a second
// chrome.sidePanel.open() on an already-open panel is a no-op (no remount) —
// so this is NOT a one-shot-forever guard. `take()` dedups by the handoff's
// own `at` timestamp (the background stamps every stash with Date.now()):
// a handoff is applied only if its `at` is strictly newer than the last one
// applied, which both (a) collapses the mount-read racing an onChanged event
// for the SAME value (they share one `at`) and (b) lets a genuinely NEWER
// right-click — the analyst triaging alert A, then highlighting script B —
// re-apply and replace what's showing. A handoff older than PENDING_TTL_MS
// (mirroring Popup.tsx) is ignored outright, so a stale `pending` left behind
// doesn't replay when the panel is opened via Chrome's own side-panel UI.
// The stash is removed once consumed either way.

import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react'
import { DEFAULT_ORIGIN, detectType, normalizeOrigin, refang } from '@socdesk/shared/indicators'
import { routeSelection } from '@socdesk/shared/intent'
import { AnalyzerResult, usePsAnalysis } from '@socdesk/shared/analyzer-ui'
import { EscalationCard, detectTheme, type CanvasTheme } from '@socdesk/shared/verdict-cards'
import { fetchEnrich, type VerdictData } from '@socdesk/shared/verdict'
import { SdMonogram } from '@socdesk/shared/ui'

type Mode = { kind: 'idle' } | { kind: 'analyze'; script: string } | { kind: 'lookup'; q: string }

/** Shape of the background's session-storage handoff, as read here — just
 *  enough to route (routeSelection re-derives mode/type from `q` itself) and
 *  to dedup/expire by `at`. */
type PendingHandoff = { q?: string; at?: number }

/** Ignore a pending handoff older than this — mirrors Popup.tsx's own
 *  PENDING_TTL_MS, same value, same reasoning: a stale stash left behind
 *  shouldn't replay into a panel opened some other way. */
const PENDING_TTL_MS = 120_000

export function Panel() {
  const [origin, setOrigin] = useState(DEFAULT_ORIGIN)
  const [input, setInput] = useState('')
  const [mode, setMode] = useState<Mode>({ kind: 'idle' })
  const theme: CanvasTheme = detectTheme()
  const lastAppliedAt = useRef(0)

  const apply = useCallback((raw: string) => {
    const route = routeSelection(raw)
    setInput(raw)
    if (route.mode === 'analyze') setMode({ kind: 'analyze', script: route.q })
    else if (route.mode === 'lookup') setMode({ kind: 'lookup', q: route.q })
    else setMode({ kind: 'idle' })
  }, [])

  useEffect(() => {
    let cancelled = false

    const take = (p?: PendingHandoff) => {
      if (cancelled || !p?.q) return
      const at = p.at ?? 0
      if (at <= lastAppliedAt.current || Date.now() - at >= PENDING_TTL_MS) return
      lastAppliedAt.current = at
      void chrome.storage.session.remove('pending')
      apply(p.q)
    }

    const onChanged = (changes: Record<string, chrome.storage.StorageChange>, area: string) => {
      if (area === 'session' && changes.pending?.newValue) take(changes.pending.newValue as PendingHandoff)
    }
    chrome.storage.onChanged.addListener(onChanged)

    void (async () => {
      try {
        const { origin: stored } = (await chrome.storage.sync.get('origin')) as { origin?: string }
        if (!cancelled) setOrigin(normalizeOrigin(stored))
      } catch { /* default */ }
      try {
        const { pending } = (await chrome.storage.session.get('pending')) as { pending?: PendingHandoff }
        take(pending)
      } catch { /* none */ }
    })()

    return () => {
      cancelled = true
      chrome.storage.onChanged.removeListener(onChanged)
    }
  }, [apply])

  const onSubmit = (e: FormEvent) => { e.preventDefault(); apply(input) }

  return (
    <div className="flex min-h-screen flex-col">
      <header className="flex items-center gap-2 border-b border-line px-4 py-3">
        <SdMonogram className="h-5 w-auto text-paper" />
        <span className="font-display text-sm font-bold tracking-tight text-paper">SOCDesk</span>
        <span className="ml-auto font-mono text-micro tracking-label text-faint">TLP:CLEAR</span>
      </header>
      <form onSubmit={onSubmit} className="px-4 pt-3">
        <textarea
          value={input}
          onChange={(e) => setInput(e.target.value)}
          spellCheck={false}
          rows={3}
          placeholder="Paste a command/script to analyze, or an indicator to look up"
          className="w-full resize-y rounded-md border border-line bg-field px-3 py-2 font-mono text-xs text-paper placeholder:text-faint focus-visible:border-line-bright"
        />
      </form>
      <main className="px-4 py-3">
        {mode.kind === 'idle' && (
          <p className="rounded-md border border-line bg-panel px-3 py-2.5 text-xs text-muted">
            Highlight a command in your console and choose <b className="font-semibold text-paper">Check in SOCDesk</b>, or paste above.
          </p>
        )}
        {mode.kind === 'analyze' && <AnalyzeBody script={mode.script} baseUrl={origin} />}
        {mode.kind === 'lookup' && <LookupBody q={mode.q} baseUrl={origin} theme={theme} />}
      </main>
    </div>
  )
}

function AnalyzeBody({ script, baseUrl }: { script: string; baseUrl: string }) {
  const state = usePsAnalysis(script)
  if (state.kind === 'analyzing' || state.kind === 'idle')
    return <p className="font-mono text-micro text-faint">Analyzing…</p>
  if (state.kind === 'error')
    return <p className="font-mono text-micro text-verdict-amber">Analysis failed: {state.message}</p>
  return <AnalyzerResult result={state.result} baseUrl={baseUrl} />
}

function LookupBody({ q, baseUrl, theme }: { q: string; baseUrl: string; theme: CanvasTheme }) {
  const [data, setData] = useState<VerdictData | null>(null)
  const [err, setErr] = useState<string | null>(null)
  useEffect(() => {
    let live = true
    setData(null); setErr(null)
    void fetchEnrich(detectType(refang(q)), refang(q), { baseUrl }).then((o) => {
      if (!live) return
      if (o.status === 'ok') setData(o.data)
      else setErr(o.reason)
    })
    return () => { live = false }
  }, [q, baseUrl])
  if (err) return <p className="font-mono text-micro text-verdict-amber">Lookup unavailable: {err}</p>
  if (!data) return <p className="font-mono text-micro text-faint">Checking {q}…</p>
  return <EscalationCard data={data} theme={theme} baseUrl={baseUrl} />
}
