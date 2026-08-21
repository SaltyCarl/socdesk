// ReportForm — sign-in gate + the report form + an invisible/managed
// Turnstile challenge. Signed-out analysts see a non-accusatory sign-in
// prompt (reporting needs attribution; look-ups never do); signed-in
// analysts get the category/evidence/comment form, which POSTs to
// /api/report on submit. Turnstile is loaded lazily (only once signed in)
// by injecting its script and polling for the global, then rendered into
// the ref'd div — CSP allows challenges.cloudflare.com for exactly this.

import { useEffect, useRef, useState } from 'react'
import type { IndicatorType } from '@socdesk/shared/indicators'
import { useSession } from './useSession'

const CATEGORIES = [
  'brute-force',
  'ssh',
  'port-scan',
  'web-app-attack',
  'phishing',
  'malware-c2',
  'scanner',
  'spam',
  'exploited-host',
  'other',
]

export function ReportForm({
  iocType,
  iocValue,
  onClose,
}: {
  iocType: IndicatorType
  iocValue: string
  onClose: () => void
}) {
  const session = useSession()
  const [category, setCategory] = useState('scanner')
  const [evidence, setEvidence] = useState('')
  const [comment, setComment] = useState('')
  const [state, setState] = useState<'idle' | 'sending' | 'done' | string>('idle')
  const tokenRef = useRef<string>('')
  const widgetRef = useRef<HTMLDivElement>(null)

  // Load Turnstile + render the (invisible/managed) widget once signed in.
  useEffect(() => {
    if (session.status !== 'in' || !widgetRef.current) return
    const s = document.createElement('script')
    s.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js'
    s.async = true
    document.head.appendChild(s)
    const id = setInterval(() => {
      // @ts-expect-error injected global
      if (window.turnstile && widgetRef.current && !widgetRef.current.dataset.rendered) {
        widgetRef.current.dataset.rendered = '1'
        // @ts-expect-error injected global
        window.turnstile.render(widgetRef.current, {
          sitekey: import.meta.env.VITE_TURNSTILE_SITEKEY,
          callback: (t: string) => {
            tokenRef.current = t
          },
        })
        clearInterval(id)
      }
    }, 200)
    return () => clearInterval(id)
  }, [session.status])

  const submit = async () => {
    setState('sending')
    const r = await fetch('/api/report', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        ioc_type: iocType,
        ioc_value: iocValue,
        category,
        evidence,
        comment,
        turnstileToken: tokenRef.current,
      }),
    })
    if (r.ok) setState('done')
    else {
      const b = await r.json().catch(() => ({}))
      setState(b.reason || `error ${r.status}`)
    }
  }

  return (
    <div className="mt-3 rounded-md border border-line bg-panel p-3 text-xs">
      {session.status === 'loading' && <p className="text-faint">…</p>}
      {session.status === 'out' && (
        <div className="flex flex-col gap-2">
          <p className="text-muted">
            Reporting needs a quick GitHub sign-in (so reports are attributable). Look-ups never do.
          </p>
          <a
            href={`/api/auth/github/start?return=${encodeURIComponent(location.pathname + location.hash)}`}
            className="self-start rounded-md border border-line px-2 py-1 font-mono text-micro text-paper hover:border-line-bright"
          >
            Sign in with GitHub
          </a>
        </div>
      )}
      {session.status === 'in' && state !== 'done' && (
        <div className="flex flex-col gap-2">
          <span className="font-mono text-micro text-faint">Reporting {iocValue}</span>
          <select
            value={category}
            onChange={(e) => setCategory(e.target.value)}
            className="rounded-md border border-line bg-field px-2 py-1"
          >
            {CATEGORIES.map((c) => (
              <option key={c} value={c}>
                {c}
              </option>
            ))}
          </select>
          <textarea
            value={evidence}
            onChange={(e) => setEvidence(e.target.value)}
            required
            maxLength={2000}
            rows={3}
            placeholder="Evidence (what you observed) — don't paste sensitive/internal data"
            className="rounded-md border border-line bg-field px-2 py-1 font-mono"
          />
          <input
            value={comment}
            onChange={(e) => setComment(e.target.value)}
            maxLength={1000}
            placeholder="Optional comment"
            className="rounded-md border border-line bg-field px-2 py-1"
          />
          <div ref={widgetRef} />
          {typeof state === 'string' && state !== 'idle' && state !== 'sending' && (
            <p className="text-verdict-amber">{state}</p>
          )}
          <div className="flex gap-2">
            <button
              type="button"
              disabled={!evidence.trim() || state === 'sending'}
              onClick={submit}
              className="rounded-md border border-line px-2 py-1 text-paper disabled:opacity-50"
            >
              Submit report
            </button>
            <button type="button" onClick={onClose} className="text-faint hover:text-paper">
              Cancel
            </button>
          </div>
        </div>
      )}
      {state === 'done' && (
        <p className="text-verdict-green">
          Queued for review — thanks. Track it in{' '}
          <a href="/reports" className="underline">
            My reports
          </a>
          .
        </p>
      )}
    </div>
  )
}
