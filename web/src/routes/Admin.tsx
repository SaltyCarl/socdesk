// Admin — the owner-only moderation console (routable, hidden from the top
// nav and the command palette; reached by direct URL — docs/OPERATIONS.md
// documents the OWNER_GITHUB_ID setup this route depends on). Mirrors
// MyReports.tsx's fetch-and-branch shape, plus the 403 branch MyReports
// doesn't need. React escapes all text — no HTML rendering of report fields
// (evidence/comment/login are attacker-influenced free text from a
// signed-in-but-otherwise-untrusted analyst).

import { useEffect, useState } from 'react'
import { Button, Chip, MicroLabel, Panel } from '../components/ui'
import { ViewHeader } from '../components/views/ViewFrame'
import { Notice } from '../components/lookup/LookupStates'
import { removeFromQueue, type QueuedReport } from './adminModel'

export function Admin() {
  const [rows, setRows] = useState<QueuedReport[] | null>(null)
  const [authState, setAuthState] = useState<'ok' | 'signedout' | 'forbidden' | 'error'>('ok')
  const [pending, setPending] = useState<Set<string>>(new Set())
  const [rowError, setRowError] = useState<Record<string, string>>({})

  useEffect(() => {
    fetch('/api/admin/reports', { credentials: 'same-origin' })
      .then(async (r) => {
        if (r.status === 401) return setAuthState('signedout')
        if (r.status === 403) return setAuthState('forbidden')
        if (!r.ok) return setAuthState('error')
        const b = await r.json()
        setRows(b.reports ?? [])
      })
      .catch(() => setAuthState('error'))
  }, [])

  const act = async (id: string, action: 'approve' | 'reject') => {
    setPending((s) => new Set(s).add(id))
    setRowError((e) => ({ ...e, [id]: '' }))
    try {
      const r = await fetch('/api/admin/moderate', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ id, action }),
      })
      if (!r.ok) throw new Error(String(r.status))
      setRows((rs) => (rs ? removeFromQueue(rs, id) : rs))
    } catch {
      setRowError((e) => ({ ...e, [id]: 'Action failed — try again.' }))
    } finally {
      setPending((s) => {
        const n = new Set(s)
        n.delete(id)
        return n
      })
    }
  }

  return (
    <div className="flex flex-col gap-8">
      <ViewHeader
        eyebrow="Owner console"
        title="Report moderation queue"
        intro="Reports waiting for a decision. Approving or rejecting here only changes the report's status — nothing here publishes to a lookup card."
        aside={rows && <MicroLabel tone="muted">{rows.length} queued</MicroLabel>}
      />

      {authState === 'signedout' ? (
        <Notice eyebrow="Sign in" title="Sign in to view the moderation queue">
          This console needs a GitHub sign-in.{' '}
          <a href="/api/auth/github/start?return=/admin" className="text-accent underline">
            Sign in with GitHub
          </a>
          .
        </Notice>
      ) : authState === 'forbidden' ? (
        <Notice eyebrow="Not authorized" title="This console is owner-only">
          Your account isn&rsquo;t the configured SOCDesk owner.
        </Notice>
      ) : authState === 'error' ? (
        <Notice eyebrow="Error" title="Couldn't load the queue">
          Something went wrong reaching the report store — try again.
        </Notice>
      ) : !rows ? (
        <p className="text-xs text-muted">Loading the queue…</p>
      ) : rows.length === 0 ? (
        <Notice eyebrow="Empty" title="Nothing waiting for review">
          The moderation queue is empty.
        </Notice>
      ) : (
        <Panel padding="none">
          <ul className="overflow-hidden rounded-lg">
            {rows.map((r) => (
              <li
                key={r.id}
                className="flex flex-col gap-3 border-b border-line px-4 py-3 last:border-0 even:bg-panel-soft/40"
              >
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div className="flex min-w-0 flex-1 flex-col gap-0.5">
                    <span className="break-all font-mono text-xs font-semibold text-paper">
                      {r.ioc_value}
                    </span>
                    <span className="font-mono text-micro text-muted">
                      {r.ioc_type} · reported by {r.login ? `@${r.login}` : `#${r.github_id}`} ·{' '}
                      {r.created_at.slice(0, 10)}
                    </span>
                  </div>
                  <div className="flex shrink-0 items-center gap-3">
                    <a
                      href={`/#q=${encodeURIComponent(r.ioc_value)}`}
                      className="font-mono text-micro text-accent underline underline-offset-2 hover:no-underline"
                    >
                      Check reputation <span aria-hidden="true">→</span>
                    </a>
                    <Chip variant="neutral">{r.category}</Chip>
                  </div>
                </div>
                <p className="whitespace-pre-wrap text-xs leading-relaxed text-muted">{r.evidence}</p>
                {r.comment && <p className="whitespace-pre-wrap text-micro text-muted">{r.comment}</p>}
                <div className="flex items-center gap-2">
                  <Button
                    variant="primary"
                    size="sm"
                    disabled={pending.has(r.id)}
                    aria-label={`Approve ${r.ioc_value}`}
                    onClick={() => act(r.id, 'approve')}
                  >
                    Approve
                  </Button>
                  <Button
                    variant="danger"
                    size="sm"
                    disabled={pending.has(r.id)}
                    aria-label={`Reject ${r.ioc_value}`}
                    onClick={() => act(r.id, 'reject')}
                  >
                    Reject
                  </Button>
                  {rowError[r.id] && (
                    <span role="status" aria-live="polite" className="text-micro text-muted">
                      {rowError[r.id]}
                    </span>
                  )}
                </div>
              </li>
            ))}
          </ul>
        </Panel>
      )}
    </div>
  )
}
