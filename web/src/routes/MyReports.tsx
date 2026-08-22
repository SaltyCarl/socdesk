// MyReports — the author's own report-status view (routable-but-hidden; reached
// from the account menu + the post-submit link). Reads GET /api/report/mine;
// React escapes all text — no HTML rendering of report fields.

import { useEffect, useState } from 'react'
import { Chip, MicroLabel, Panel } from '../components/ui'
import { ViewHeader } from '../components/views/ViewFrame'
import { Notice } from '../components/lookup/LookupStates'
import { markContributorSeen } from '../lib/contributorSeen'
import { statusChipVariant } from './myReportsModel'

type Row = {
  id: string
  ioc_type: string
  ioc_value: string
  category: string
  status: string
  created_at: string
}

export function MyReports() {
  const [rows, setRows] = useState<Row[] | null>(null)
  const [auth, setAuth] = useState(true)
  const [error, setError] = useState(false)

  useEffect(() => {
    markContributorSeen()
    fetch('/api/report/mine', { credentials: 'same-origin' })
      .then(async (r) => {
        if (r.status === 401) return setAuth(false)
        if (!r.ok) return setError(true)
        const b = await r.json()
        setRows(b.reports ?? [])
      })
      .catch(() => setError(true))
  }, [])

  return (
    <div className="flex flex-col gap-8">
      <ViewHeader
        eyebrow="My reports"
        title="Your submitted indicators"
        intro="Every indicator you've reported and where it sits in review. Visible only to you."
      />

      {!auth ? (
        <Notice eyebrow="Sign in" title="Sign in to see your reports">
          Reporting is attributable, so this view needs a GitHub sign-in.{' '}
          <a href="/api/auth/github/start?return=/reports" className="text-accent underline">
            Sign in with GitHub
          </a>
          .
        </Notice>
      ) : error ? (
        <Notice eyebrow="Error" title="Couldn't load your reports">
          Something went wrong reaching the report store — try again.
        </Notice>
      ) : !rows ? (
        <p className="text-xs text-muted">Loading your reports…</p>
      ) : rows.length === 0 ? (
        <Notice eyebrow="Empty" title="No reports yet">
          When you report an indicator from a lookup card, it will appear here as “queued”.
        </Notice>
      ) : (
        <Panel padding="none">
          <ul className="overflow-hidden rounded-lg">
            {rows.map((r) => (
              <li
                key={r.id}
                className="flex items-start gap-3 border-b border-line px-4 py-3 last:border-0 even:bg-panel-soft/40"
              >
                <span className="flex w-[132px] shrink-0 flex-col items-start gap-1.5">
                  <Chip variant={statusChipVariant(r.status)}>{r.status}</Chip>
                  <span className="font-mono text-micro text-muted">{r.created_at.slice(0, 10)}</span>
                </span>
                <span className="flex min-w-0 flex-1 flex-col gap-0.5">
                  <span className="break-all font-mono text-xs font-semibold text-paper">{r.ioc_value}</span>
                  <MicroLabel tone="muted">{r.category}</MicroLabel>
                </span>
              </li>
            ))}
          </ul>
        </Panel>
      )}
    </div>
  )
}
