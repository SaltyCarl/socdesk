// MyReports — the author's own report-status view (routable-but-hidden, like
// /gallery: reached from the report-submitted confirmation link, not the top
// nav). Reads GET /api/report/mine; React escapes all text below — no HTML
// rendering of report/category/status fields.

import { useEffect, useState } from 'react'

type Row = { id: string; ioc_type: string; ioc_value: string; category: string; status: string; created_at: string }

export function MyReports() {
  const [rows, setRows] = useState<Row[] | null>(null)
  const [auth, setAuth] = useState(true)
  useEffect(() => {
    fetch('/api/report/mine', { credentials: 'same-origin' })
      .then(async (r) => {
        if (r.status === 401) {
          setAuth(false)
          return
        }
        const b = await r.json()
        setRows(b.reports ?? [])
      })
      .catch(() => setRows([]))
  }, [])
  if (!auth)
    return (
      <p className="p-4 text-xs text-muted">
        Sign in to see your reports.{' '}
        <a href="/api/auth/github/start?return=/reports" className="underline">
          Sign in with GitHub
        </a>
        .
      </p>
    )
  if (!rows) return <p className="p-4 text-xs text-faint">…</p>
  if (!rows.length) return <p className="p-4 text-xs text-muted">No reports yet.</p>
  return (
    <ul className="flex flex-col gap-1 p-4">
      {rows.map((r) => (
        <li key={r.id} className="flex items-center gap-2 font-mono text-xs">
          <span className="w-14 text-faint">{r.status}</span>
          <span className="text-paper">{r.ioc_value}</span>
          <span className="text-muted">{r.category}</span>
          <span className="ml-auto text-faint">{r.created_at.slice(0, 10)}</span>
        </li>
      ))}
    </ul>
  )
}
