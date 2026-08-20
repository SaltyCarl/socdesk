// Popup.tsx — the real toolbar popup UX (Phase 2).
//
// Flow: the analyst pastes an indicator (or arrives pre-loaded from the context
// menu), we refang + classify it with the shared indicator logic, then call the
// LIVE /api/enrich on the configured origin through the shared verdict client.
// The mapped VerdictData renders in the shared EscalationCard (full client
// register — heroes, chips, Compare-IP, copy actions), the same card the web app
// shows, with a collapsed copy-card preview below. CVE/email (not served by
// /api/enrich) and any error resolve to an HONEST state — never a fabricated verdict.
//
// SECURITY: every value in the enrich response is attacker-influenced. Nothing
// is ever interpolated into HTML — React escapes text, and the source verify
// links inside the shared card are already run through safeUrl in the shared
// layer. The live fetch is a cross-origin call the manifest host_permissions
// authorise (socdesk.io / socdesk.pages.dev).

import {
  useCallback,
  useEffect,
  useRef,
  useState,
  type FormEvent,
  type ReactNode,
} from 'react'
import {
  DEFAULT_ORIGIN,
  detectType,
  isEnrichable,
  normalizeOrigin,
  refang,
  reportUrl,
  type IndicatorType,
} from '@socdesk/shared/indicators'
import { fetchEnrich, type VerdictData } from '@socdesk/shared/verdict'
import { Button, Chip, SdMonogram } from '@socdesk/shared/ui'
import {
  CardCanvasPreview,
  EscalationCard,
  detectTheme,
  type CanvasTheme,
} from '@socdesk/shared/verdict-cards'

const TYPE_LABEL: Record<Exclude<IndicatorType, ''>, string> = {
  ipv4: 'IPv4',
  ipv6: 'IPv6',
  domain: 'Domain',
  url: 'URL',
  md5: 'MD5',
  sha1: 'SHA-1',
  sha256: 'SHA-256',
  cve: 'CVE',
  email: 'Email',
}

/** The one-shot lookup handed over by the background service worker. */
interface Pending {
  q?: string
  /** Present on every handoff since the side-panel analyzer shipped (Task 3
   *  routes `analyze` to the panel instead) — the popup only ever receives a
   *  `lookup` handoff, so this is read for shape-compatibility only and does
   *  not change behaviour here. */
  mode?: 'lookup'
  /** Epoch ms the context-menu click happened; used to ignore a stale handoff
   *  left behind when chrome.action.openPopup was unavailable and the click
   *  fell back to a report tab instead of opening this popup. */
  at?: number
}

/** Ignore a pending handoff older than this — it belongs to an earlier click
 *  that never actually opened the popup. */
const PENDING_TTL_MS = 120_000

/** The popup's view state — a small, honest state machine. */
type View =
  | { kind: 'idle' }
  | { kind: 'invalid'; q: string }
  | { kind: 'nonEnrichable'; q: string; type: Exclude<IndicatorType, ''> }
  | { kind: 'loading'; q: string }
  | { kind: 'ok'; data: VerdictData }
  | { kind: 'declined'; reason: string }
  | { kind: 'unavailable'; reason: string }

export function Popup() {
  const [input, setInput] = useState('')
  const [origin, setOrigin] = useState(DEFAULT_ORIGIN)
  const [lastQ, setLastQ] = useState('')
  const [view, setView] = useState<View>({ kind: 'idle' })
  const inputRef = useRef<HTMLInputElement>(null)
  // Guards against an out-of-order fetch: only the latest run updates the view.
  const reqId = useRef(0)

  // The theme was resolved before first paint by initTheme(); read it once for
  // the canvas copy-card (which can't read CSS vars).
  const theme: CanvasTheme = detectTheme()

  const run = useCallback(async (raw: string, resolvedOrigin: string) => {
    const q = refang(raw)
    setInput(q)
    setLastQ(q)
    if (!q) {
      setView({ kind: 'idle' })
      return
    }
    const type = detectType(q)
    if (!type) {
      setView({ kind: 'invalid', q })
      return
    }
    if (!isEnrichable(type)) {
      // CVE / email — not enriched by design; the full report handles these.
      setView({ kind: 'nonEnrichable', q, type })
      return
    }

    const id = ++reqId.current
    setView({ kind: 'loading', q })
    const outcome = await fetchEnrich(type, q, { baseUrl: resolvedOrigin })
    if (id !== reqId.current) return // superseded by a newer lookup

    if (outcome.status === 'ok') setView({ kind: 'ok', data: outcome.data })
    else if (outcome.status === 'declined') setView({ kind: 'declined', reason: outcome.reason })
    else setView({ kind: 'unavailable', reason: outcome.reason })
  }, [])

  // Boot: resolve the origin from Options, then auto-run any pending context-menu
  // lookup (the primary flow: right-click an indicator → popup opens pre-loaded).
  useEffect(() => {
    let cancelled = false
    void (async () => {
      let resolved = DEFAULT_ORIGIN
      try {
        const { origin: stored } = (await chrome.storage.sync.get('origin')) as {
          origin?: string
        }
        resolved = normalizeOrigin(stored)
      } catch {
        /* storage blocked — keep the default */
      }
      if (cancelled) return
      setOrigin(resolved)

      let pending: Pending | undefined
      try {
        const s = (await chrome.storage.session.get('pending')) as { pending?: Pending }
        pending = s.pending
        if (pending) await chrome.storage.session.remove('pending') // one-shot
      } catch {
        /* session storage unavailable */
      }
      if (cancelled) return

      inputRef.current?.focus()
      const fresh = !pending?.at || Date.now() - pending.at < PENDING_TTL_MS
      if (pending?.q && fresh) void run(pending.q, resolved)
    })()
    return () => {
      cancelled = true
    }
  }, [run])

  const onSubmit = (e: FormEvent) => {
    e.preventDefault()
    void run(input, origin)
  }

  const openReport = useCallback(() => {
    const q = lastQ || refang(input)
    const url = q ? reportUrl(origin, q) : `${normalizeOrigin(origin)}/`
    chrome.tabs.create({ url })
  }, [lastQ, input, origin])

  const openOptions = () => chrome.runtime.openOptionsPage()

  const liveType = detectType(refang(input))

  return (
    <div className="flex flex-col">
      <header className="flex items-center gap-2 border-b border-line px-4 py-3">
        <SdMonogram className="h-5 w-auto text-paper" />
        <span className="font-display text-sm font-bold tracking-tight text-paper">SOCDesk</span>
        <span
          className="ml-auto font-mono text-micro tracking-label text-faint"
          title="Nothing here is classified"
        >
          TLP:CLEAR
        </span>
      </header>

      <form onSubmit={onSubmit} className="px-4 pt-3" autoComplete="off">
        <div className="relative">
          <input
            ref={inputRef}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            spellCheck={false}
            autoComplete="off"
            placeholder="Paste an indicator — IP, domain, URL, hash"
            aria-label="Indicator"
            className="w-full rounded-md border border-line bg-field px-3 py-2 pr-24 font-mono text-xs text-paper placeholder:text-faint focus-visible:border-line-bright"
          />
          {liveType && (
            <span className="pointer-events-none absolute right-2 top-1/2 -translate-y-1/2">
              <Chip variant={isEnrichable(liveType) ? 'accent' : 'neutral'}>
                {TYPE_LABEL[liveType]}
              </Chip>
            </span>
          )}
        </div>
      </form>

      <main className="px-4 py-3">
        <ViewBody view={view} theme={theme} onReport={openReport} baseUrl={origin} />
      </main>

      <footer className="flex items-center justify-between gap-2 border-t border-line px-4 py-2.5">
        <button
          type="button"
          onClick={openReport}
          className="font-mono text-micro text-muted transition-colors hover:text-paper"
        >
          Open full report ↗
        </button>
        <button
          type="button"
          onClick={openOptions}
          className="font-mono text-micro text-faint transition-colors hover:text-paper"
        >
          Options
        </button>
      </footer>
    </div>
  )
}

/* ---------- the view states --------------------------------------------- */

function ViewBody({
  view,
  theme,
  onReport,
  baseUrl,
}: {
  view: View
  theme: CanvasTheme
  onReport: () => void
  baseUrl: string
}) {
  switch (view.kind) {
    case 'idle':
      return (
        <Notice>
          Paste an indicator above, or select text on a page and choose{' '}
          <b className="font-semibold text-paper">Check in SOCDesk</b>.
        </Notice>
      )
    case 'invalid':
      return (
        <NoticeWithReport onReport={onReport}>
          “{view.q}” isn’t a recognizable indicator. Open the full report to search it in SOCDesk.
        </NoticeWithReport>
      )
    case 'nonEnrichable':
      return (
        <NoticeWithReport onReport={onReport}>
          {TYPE_LABEL[view.type]} isn’t a live-enriched type — CVEs and emails open in the full
          report.
        </NoticeWithReport>
      )
    case 'loading':
      return <LoadingSkeleton q={view.q} />
    case 'declined':
      return (
        <Notice>
          Live enrichment declined: {view.reason}. Open the full report for the static verdict.
        </Notice>
      )
    case 'unavailable':
      return (
        <Notice>
          Live reputation unavailable: {view.reason}. Check the origin in Options, or open the full
          report.
        </Notice>
      )
    case 'ok':
      return <Result data={view.data} theme={theme} baseUrl={baseUrl} />
  }
}

function Result({
  data,
  theme,
  baseUrl,
}: {
  data: VerdictData
  theme: CanvasTheme
  baseUrl: string
}) {
  return (
    <div className="flex flex-col gap-3">
      <EscalationCard data={data} theme={theme} baseUrl={baseUrl} />
      {data.partial && (
        <p className="font-mono text-micro text-faint">
          Partial — one or more sources were unavailable.
        </p>
      )}
      <CardPreviewDisclosure data={data} theme={theme} />
    </div>
  )
}

/** Collapsed copy-card preview — keeps the popup short; the canvas is only drawn
 *  once the analyst opens the disclosure. */
function CardPreviewDisclosure({ data, theme }: { data: VerdictData; theme: CanvasTheme }) {
  const [open, setOpen] = useState(false)
  return (
    <details
      className="overflow-hidden rounded-md border border-line bg-panel"
      onToggle={(e) => setOpen(e.currentTarget.open)}
    >
      <summary className="cursor-pointer select-none list-none px-3 py-2 font-mono text-micro uppercase tracking-label text-muted transition-colors hover:text-paper [&::-webkit-details-marker]:hidden">
        Preview copy-card
      </summary>
      <div className="border-t border-line p-3">
        {open && <CardCanvasPreview data={data} theme={theme} />}
      </div>
    </details>
  )
}

function LoadingSkeleton({ q }: { q: string }) {
  return (
    <div className="flex flex-col gap-3" aria-live="polite">
      <p className="flex items-center gap-2 font-mono text-micro text-faint">
        <span
          aria-hidden="true"
          className="inline-block size-1.5 shrink-0 animate-ping rounded-full bg-accent"
        />
        Checking public reputation sources for {q}…
      </p>
      <div className="flex flex-col gap-2">
        {[0, 1, 2].map((i) => (
          <div key={i} className="h-9 animate-pulse rounded-md bg-panel-soft" />
        ))}
      </div>
    </div>
  )
}

/* ---------- honest notices (never a fabricated verdict) ------------------ */

function Notice({ children }: { children: ReactNode }) {
  return (
    <p className="rounded-md border border-line bg-panel px-3 py-2.5 text-xs leading-relaxed text-muted">
      {children}
    </p>
  )
}

function NoticeWithReport({
  children,
  onReport,
}: {
  children: ReactNode
  onReport: () => void
}) {
  return (
    <div className="flex flex-col gap-3">
      <Notice>{children}</Notice>
      <Button variant="primary" size="sm" className="self-start" onClick={onReport}>
        Open full report ↗
      </Button>
    </div>
  )
}
