// Lookup.tsx — the LIVE escalation-card surface (the product's north star:
// "IOC in → OSINT out"). An analyst types (or deep-links via `#q=`) one
// indicator; `useLookup` refangs, type-detects, and resolves it:
//
//   * enrichable (ip / domain / url / md5 / sha1 / sha256) → /api/enrich, mapped
//     into the shared VerdictData and rendered as the real EscalationCard + its
//     deterministic copy-card PNG + the analyst console.
//   * CVE → resolved from the committed KEV/CVSS/EPSS snapshot (cves.json) into
//     the same VerdictData (authoritative single-source, not enriched).
//   * anything else → an honest inline message (never a fabricated verdict).
//
// The resolver (useLookup) and the honest non-ok renderings (LookupStatus) are
// shared with the landing inline card, so both surfaces resolve identically and
// word every degraded state the same. /api/enrich is a Cloudflare Pages Function
// — there is no local Function, so the enrichable path reads "unavailable" in
// local preview; that is the CORRECT honest state, not a bug.

import { useEffect, useRef, useState, type FormEvent, type ReactNode } from 'react'
import { cx } from '@socdesk/shared/lib/cx'
import { isEnrichable, refang } from '@socdesk/shared/indicators'
import { classifyCockpitInput } from '@socdesk/shared/intent'
import type { VerdictData } from '@socdesk/shared/verdict'
import {
  AnalystVerdict,
  CardCanvasPreview,
  EscalationCard,
  STUBS,
  useEffectiveTheme,
  type EffectiveTheme,
} from '@socdesk/shared/verdict-cards'
import { Button, MicroLabel } from '../components/ui'
import { lookupHash, navigate } from '../components/palette/commands'
import { useLookup } from '../components/lookup/useLookup'
import { LookupStatus } from '../components/lookup/LookupStates'
import { ReportButton } from '../components/report/ReportButton'
import { readLookupQuery } from './lookupModel'

/** A few worked examples — a Tor exit IP, a young phishing domain, a real KEV
 *  CVE (resolves offline from the catalog), a benign IP. Clicking one submits
 *  it, exactly as typing would. */
const EXAMPLES = ['185.220.101.42', 'secure-account-verify.com', 'CVE-2026-9198', '8.8.8.8']

const CHIP_CLS =
  'rounded-md border border-line bg-panel px-2.5 py-1 font-mono text-xs text-muted transition-colors duration-150 ease-brand hover:border-line-bright hover:text-paper focus-visible:outline-2 focus-visible:outline-accent break-all'

function Label({ children }: { children: ReactNode }) {
  return (
    <MicroLabel tone="faint" className="mb-3">
      {children}
    </MicroLabel>
  )
}

/* ---------- the shared card layout (client + copy-card + console) --------- */

/** Both registers over one VerdictData: the client escalation card + its
 *  deterministic copy-card PNG (left), the dense analyst console (right).
 *  EscalationCard embeds the copy-card / copy-text CardActions itself.
 *  `reportable` mounts the low-key report affordance under the escalation
 *  card footer — set only by the real resolved-lookup call site, never by
 *  the static ExamplesGallery (reporting a canned stub makes no sense). */
function CardTriptych({
  data,
  theme,
  reportable,
}: {
  data: VerdictData
  theme?: EffectiveTheme
  reportable?: boolean
}) {
  return (
    <div className="grid gap-8 lg:grid-cols-2">
      <div className="flex flex-col gap-8">
        <div>
          <Label>Client register — escalation card</Label>
          <EscalationCard data={data} theme={theme} />
          {reportable && (
            <div className="mt-2">
              <ReportButton iocType={data.type} iocValue={data.indicator} />
            </div>
          )}
        </div>
        <div>
          <Label>Copy card — deterministic PNG on the clipboard</Label>
          <div className="rounded-lg border border-dashed border-line-bright bg-ink p-5">
            <CardCanvasPreview data={data} theme={theme} />
          </div>
        </div>
      </div>
      <div>
        <Label>Analyst register — console</Label>
        <AnalystVerdict data={data} />
      </div>
    </div>
  )
}

/* ---------- the idle examples gallery ------------------------------------ */

/** The static reference gallery — one card per indicator family — shown while
 *  no lookup is active, so a first-time visitor sees what a result looks like. */
function ExamplesGallery({ theme }: { theme?: EffectiveTheme }) {
  const [sel, setSel] = useState(STUBS[0].id)
  const stub = STUBS.find((s) => s.id === sel) ?? STUBS[0]

  return (
    <div className="flex flex-col gap-6 border-t border-line pt-8">
      <div className="flex flex-col gap-3">
        <MicroLabel tone="faint" tick>
          Examples — sample cards, one per indicator family
        </MicroLabel>
        <div className="flex flex-wrap gap-2" role="tablist" aria-label="Example indicator type">
          {STUBS.map((s) => {
            const active = s.id === sel
            return (
              <button
                key={s.id}
                type="button"
                role="tab"
                aria-selected={active}
                onClick={() => setSel(s.id)}
                className={cx(
                  'inline-flex items-baseline gap-2 rounded-md border px-3 py-1.5 font-mono text-xs transition-colors duration-150 ease-brand',
                  'outline-offset-2 focus-visible:outline-2 focus-visible:outline-accent',
                  active
                    ? 'border-[var(--edge-accent)] bg-[var(--tint-accent)] text-accent'
                    : 'border-line bg-panel text-muted hover:border-line-bright hover:text-paper',
                )}
              >
                <span className="font-semibold">{s.label}</span>
                <span className="text-micro text-faint">{s.hint}</span>
              </button>
            )
          })}
        </div>
      </div>
      <CardTriptych data={stub.data} theme={theme} />
    </div>
  )
}

/* ---------- the route ---------------------------------------------------- */

export function Lookup() {
  // `rawQuery` is the SUBMITTED indicator (from the `#q=` hash) exactly as
  // read — including a command-shaped value, which must never itself reach
  // `useLookup` (see `isCommand`/`query` below). `text` is the live input
  // value. Keystrokes change only `text`; submitting writes the hash, which
  // the sync effect reflects back into both.
  const [rawQuery, setRawQuery] = useState<string>(readLookupQuery)
  const [text, setText] = useState<string>(readLookupQuery)
  const inputRef = useRef<HTMLInputElement>(null)
  const theme = useEffectiveTheme()

  // A command-shaped hash query is a bookmarked/shared-link route into the
  // SAME leak `runLookup` already guards for a form submit (§2.2) — the
  // initial mount value and the hashchange/popstate sync below both read the
  // hash directly, with no interaction to intercept. Guard them here instead:
  // a command-shaped `rawQuery` never becomes the `query` fed to `useLookup`
  // (design spec §2.1, §9).
  const isCommand = rawQuery !== '' && classifyCockpitInput(rawQuery) === 'command'
  const query = isCommand ? '' : rawQuery
  const state = useLookup(query)

  // Redirecting is a navigation side effect — it must run in an effect, never
  // during render or inside the `useState` initializer. Carries the command
  // forward on the same `#q=` deep link so a bookmarked/shared `/lookup#q=`
  // command-shaped link doesn't silently drop the paste on redirect.
  useEffect(() => {
    if (isCommand) navigate(`/analyzer${lookupHash(rawQuery)}`)
  }, [isCommand, rawQuery])

  useEffect(() => {
    // hashchange covers a raw hash edit / same-route resubmit; popstate covers a
    // cross-route deep link (commands.ts::navigate pushes state + a synthetic
    // popstate, which does NOT emit hashchange).
    const sync = () => {
      const q = readLookupQuery()
      setRawQuery(q)
      setText(q)
    }
    window.addEventListener('hashchange', sync)
    window.addEventListener('popstate', sync)
    return () => {
      window.removeEventListener('hashchange', sync)
      window.removeEventListener('popstate', sync)
    }
  }, [])

  const runLookup = (raw: string) => {
    const q = refang(raw)
    if (!q) return
    // A command-shaped paste must never drive useLookup (whose detectType
    // call has no command guard of its own) — route it to the standalone
    // analyzer instead of writing the lookup hash (design spec §2.2, §9).
    if (classifyCockpitInput(q) === 'command') {
      navigate(`/analyzer${lookupHash(q)}`)
      return
    }
    // Writing the hash drives the sync effect. An identical resubmit fires no
    // hashchange — but the result already shows it, so that is a harmless no-op.
    window.location.hash = lookupHash(q)
  }

  const onSubmit = (e: FormEvent) => {
    e.preventDefault()
    runLookup(text)
  }

  const onExample = (v: string) => {
    setText(v)
    runLookup(v)
    inputRef.current?.focus()
  }

  return (
    <div className="flex flex-col gap-8">
      <header className="border-b border-line pb-8">
        <MicroLabel tone="accent" tick>
          Escalation lookup
        </MicroLabel>
        <h1 className="mt-3 font-display text-2xl font-extrabold tracking-display text-paper">
          Indicator in, escalation card out
        </h1>
        <p className="mt-3 max-w-2xl text-md text-muted">
          One indicator, resolved live across the public sources into an honest, attributed,
          source-class-aware escalation artifact. The tally leads as coverage (never a threat
          score); every source is attributed; geo is context, never a verdict; hashes and CVEs are
          banner-led — the identity or exploitation fact leads, not a cross-source vote.
        </p>
      </header>

      <form onSubmit={onSubmit} className="flex flex-col gap-3">
        <div className="flex flex-col gap-2 sm:flex-row">
          <input
            ref={inputRef}
            value={text}
            onChange={(e) => setText(e.target.value)}
            type="text"
            inputMode="text"
            autoComplete="off"
            spellCheck={false}
            aria-label="Look up an indicator"
            placeholder="IP · domain · URL · hash · CVE — e.g. 8.8.8.8"
            className="w-full flex-1 rounded-md border border-line bg-field px-3 py-2 font-mono text-base text-paper outline-offset-2 placeholder:text-faint focus-visible:outline-2 focus-visible:outline-accent"
          />
          <Button type="submit" variant="primary">
            Look up
          </Button>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <span className="font-mono text-micro uppercase tracking-[0.14em] text-faint">Try</span>
          {EXAMPLES.map((v) => (
            <button key={v} type="button" onClick={() => onExample(v)} className={CHIP_CLS}>
              {v}
            </button>
          ))}
        </div>
      </form>

      {state.kind === 'idle' ? (
        <ExamplesGallery theme={theme} />
      ) : state.kind === 'ok' ? (
        <CardTriptych data={state.data} theme={theme} reportable={isEnrichable(state.data.type)} />
      ) : (
        <LookupStatus state={state} />
      )}
    </div>
  )
}
